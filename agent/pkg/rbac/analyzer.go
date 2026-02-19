// Package rbac provides analysis of Kubernetes RBAC configurations to identify
// security risks such as overly permissive roles and stale service accounts.
package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// Analyzer performs RBAC security analysis on a Kubernetes cluster.
// It implements the scanner.Analyzer interface.
type Analyzer struct {
	client *k8s.Client
	logger *slog.Logger
}

// Name returns the analyzer name.
func (a *Analyzer) Name() string { return "rbac" }

// NewAnalyzer creates a new RBAC analyzer.
func NewAnalyzer(client *k8s.Client, logger *slog.Logger) *Analyzer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Analyzer{
		client: client,
		logger: logger,
	}
}

// Analyze runs all RBAC checks and returns findings.
func (a *Analyzer) Analyze(ctx context.Context, namespaces []string) ([]scanner.Finding, error) {
	a.logger.Info("starting RBAC analysis")

	clusterRoles, err := a.client.ListClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster roles: %w", err)
	}

	clusterRoleBindings, err := a.client.ListClusterRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing cluster role bindings: %w", err)
	}

	var allRoles []rbacv1.Role
	var allRoleBindings []rbacv1.RoleBinding

	// Collect namespace-scoped roles and bindings.
	for _, ns := range namespaces {
		roles, err := a.client.ListRoles(ctx, ns)
		if err != nil {
			a.logger.Warn("failed to list roles", "namespace", ns, "error", err)
			continue
		}
		allRoles = append(allRoles, roles...)

		bindings, err := a.client.ListRoleBindings(ctx, ns)
		if err != nil {
			a.logger.Warn("failed to list role bindings", "namespace", ns, "error", err)
			continue
		}
		allRoleBindings = append(allRoleBindings, bindings...)
	}

	now := time.Now()
	var findings []scanner.Finding

	// Check 1: Cluster-admin bindings.
	findings = append(findings, a.checkClusterAdminBindings(clusterRoleBindings, now)...)

	// Check 2: Wildcard permissions.
	findings = append(findings, a.checkWildcardPermissions(clusterRoles, allRoles, now)...)

	// Check 3: Unused roles (roles with no bindings).
	findings = append(findings, a.checkUnusedRoles(clusterRoles, clusterRoleBindings, allRoles, allRoleBindings, now)...)

	// Check 4: Stale service accounts in bindings.
	findings = append(findings, a.checkStaleServiceAccounts(clusterRoleBindings, allRoleBindings, now)...)

	// Check 5: Roles that can escalate privileges.
	findings = append(findings, a.checkPrivilegeEscalation(clusterRoles, allRoles, now)...)

	a.logger.Info("RBAC analysis complete", "findings", len(findings))
	return findings, nil
}

// checkClusterAdminBindings identifies bindings to the cluster-admin role.
func (a *Analyzer) checkClusterAdminBindings(bindings []rbacv1.ClusterRoleBinding, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, binding := range bindings {
		if binding.RoleRef.Name != "cluster-admin" {
			continue
		}

		// Skip the default system bindings.
		if strings.HasPrefix(binding.Name, "system:") {
			continue
		}

		for _, subject := range binding.Subjects {
			findings = append(findings, scanner.Finding{
				ID:          "RBAC-001",
				Title:       "Non-default cluster-admin binding detected",
				Description: fmt.Sprintf("Subject %q (%s) is bound to cluster-admin via ClusterRoleBinding %q", subject.Name, subject.Kind, binding.Name),
				Severity:    scanner.SeverityCritical,
				Status:      scanner.StatusFail,
				Category:    "rbac",
				Resource:    fmt.Sprintf("ClusterRoleBinding/%s", binding.Name),
				Remediation: "Review whether this subject requires full cluster-admin privileges. Consider creating a more restrictive role.",
				Details: map[string]string{
					"subject_kind":      subject.Kind,
					"subject_name":      subject.Name,
					"subject_namespace": subject.Namespace,
					"binding":           binding.Name,
				},
				Timestamp: now,
			})
		}
	}

	// If no non-system cluster-admin bindings found, that is a pass.
	if len(findings) == 0 {
		findings = append(findings, scanner.Finding{
			ID:          "RBAC-001",
			Title:       "No non-default cluster-admin bindings",
			Description: "No custom ClusterRoleBindings to cluster-admin were found.",
			Severity:    scanner.SeverityCritical,
			Status:      scanner.StatusPass,
			Category:    "rbac",
			Timestamp:   now,
		})
	}

	return findings
}

// checkWildcardPermissions finds roles with wildcard verbs or resources.
func (a *Analyzer) checkWildcardPermissions(clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for _, cr := range clusterRoles {
		// Skip system roles.
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		for _, rule := range cr.Rules {
			if hasWildcard(rule.Verbs) || hasWildcard(rule.Resources) || hasWildcard(rule.APIGroups) {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-002",
					Title:       "Wildcard permission in ClusterRole",
					Description: fmt.Sprintf("ClusterRole %q has wildcard permissions: verbs=%v, resources=%v, apiGroups=%v", cr.Name, rule.Verbs, rule.Resources, rule.APIGroups),
					Severity:    scanner.SeverityHigh,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("ClusterRole/%s", cr.Name),
					Remediation: "Replace wildcard (*) with specific verbs, resources, and API groups following the principle of least privilege.",
					Details: map[string]string{
						"verbs":      strings.Join(rule.Verbs, ","),
						"resources":  strings.Join(rule.Resources, ","),
						"api_groups": strings.Join(rule.APIGroups, ","),
					},
					Timestamp: now,
				})
				break // One finding per role is sufficient.
			}
		}
	}

	for _, r := range roles {
		if strings.HasPrefix(r.Name, "system:") {
			continue
		}
		for _, rule := range r.Rules {
			if hasWildcard(rule.Verbs) || hasWildcard(rule.Resources) {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-002",
					Title:       "Wildcard permission in Role",
					Description: fmt.Sprintf("Role %s/%s has wildcard permissions: verbs=%v, resources=%v", r.Namespace, r.Name, rule.Verbs, rule.Resources),
					Severity:    scanner.SeverityHigh,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name),
					Namespace:   r.Namespace,
					Remediation: "Replace wildcard (*) with specific verbs and resources.",
					Timestamp:   now,
				})
				break
			}
		}
	}

	return findings
}

// checkUnusedRoles finds roles that have no associated bindings.
func (a *Analyzer) checkUnusedRoles(
	clusterRoles []rbacv1.ClusterRole,
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
	roles []rbacv1.Role,
	roleBindings []rbacv1.RoleBinding,
	now time.Time,
) []scanner.Finding {
	var findings []scanner.Finding

	// Build a set of bound ClusterRoles.
	boundClusterRoles := make(map[string]bool)
	for _, crb := range clusterRoleBindings {
		if crb.RoleRef.Kind == "ClusterRole" {
			boundClusterRoles[crb.RoleRef.Name] = true
		}
	}
	// RoleBindings can also reference ClusterRoles.
	for _, rb := range roleBindings {
		if rb.RoleRef.Kind == "ClusterRole" {
			boundClusterRoles[rb.RoleRef.Name] = true
		}
	}

	for _, cr := range clusterRoles {
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		if !boundClusterRoles[cr.Name] {
			findings = append(findings, scanner.Finding{
				ID:          "RBAC-003",
				Title:       "Unused ClusterRole",
				Description: fmt.Sprintf("ClusterRole %q has no associated bindings", cr.Name),
				Severity:    scanner.SeverityLow,
				Status:      scanner.StatusWarning,
				Category:    "rbac",
				Resource:    fmt.Sprintf("ClusterRole/%s", cr.Name),
				Remediation: "Remove unused ClusterRoles to reduce attack surface and simplify RBAC management.",
				Timestamp:   now,
			})
		}
	}

	// Build a set of bound namespaced Roles.
	boundRoles := make(map[string]bool) // key: "namespace/name"
	for _, rb := range roleBindings {
		if rb.RoleRef.Kind == "Role" {
			key := fmt.Sprintf("%s/%s", rb.Namespace, rb.RoleRef.Name)
			boundRoles[key] = true
		}
	}

	for _, r := range roles {
		if strings.HasPrefix(r.Name, "system:") {
			continue
		}
		key := fmt.Sprintf("%s/%s", r.Namespace, r.Name)
		if !boundRoles[key] {
			findings = append(findings, scanner.Finding{
				ID:          "RBAC-003",
				Title:       "Unused Role",
				Description: fmt.Sprintf("Role %s/%s has no associated bindings", r.Namespace, r.Name),
				Severity:    scanner.SeverityLow,
				Status:      scanner.StatusWarning,
				Category:    "rbac",
				Resource:    fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name),
				Namespace:   r.Namespace,
				Remediation: "Remove unused Roles to reduce attack surface.",
				Timestamp:   now,
			})
		}
	}

	return findings
}

// checkStaleServiceAccounts identifies bindings that reference the default
// service account, which is a security concern.
func (a *Analyzer) checkStaleServiceAccounts(
	clusterRoleBindings []rbacv1.ClusterRoleBinding,
	roleBindings []rbacv1.RoleBinding,
	now time.Time,
) []scanner.Finding {
	var findings []scanner.Finding

	for _, crb := range clusterRoleBindings {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-004",
					Title:       "Default ServiceAccount in ClusterRoleBinding",
					Description: fmt.Sprintf("ClusterRoleBinding %q grants permissions to the default ServiceAccount in namespace %q", crb.Name, subject.Namespace),
					Severity:    scanner.SeverityMedium,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("ClusterRoleBinding/%s", crb.Name),
					Namespace:   subject.Namespace,
					Remediation: "Create a dedicated ServiceAccount for workloads instead of using the default ServiceAccount.",
					Timestamp:   now,
				})
			}
		}
	}

	for _, rb := range roleBindings {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == "default" {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-004",
					Title:       "Default ServiceAccount in RoleBinding",
					Description: fmt.Sprintf("RoleBinding %s/%s grants permissions to the default ServiceAccount", rb.Namespace, rb.Name),
					Severity:    scanner.SeverityMedium,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("RoleBinding/%s/%s", rb.Namespace, rb.Name),
					Namespace:   rb.Namespace,
					Remediation: "Create a dedicated ServiceAccount for workloads instead of using the default ServiceAccount.",
					Timestamp:   now,
				})
			}
		}
	}

	return findings
}

// checkPrivilegeEscalation identifies roles that can create/modify roles or
// bindings, effectively allowing privilege escalation.
func (a *Analyzer) checkPrivilegeEscalation(clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	sensitiveResources := map[string]bool{
		"clusterroles":        true,
		"clusterrolebindings": true,
		"roles":               true,
		"rolebindings":        true,
	}

	escalatingVerbs := map[string]bool{
		"create": true,
		"update": true,
		"patch":  true,
		"*":      true,
	}

	for _, cr := range clusterRoles {
		if strings.HasPrefix(cr.Name, "system:") {
			continue
		}
		if cr.Name == "cluster-admin" || cr.Name == "admin" || cr.Name == "edit" {
			continue // Well-known roles.
		}

		for _, rule := range cr.Rules {
			if canEscalate(rule, sensitiveResources, escalatingVerbs) {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-005",
					Title:       "Potential privilege escalation in ClusterRole",
					Description: fmt.Sprintf("ClusterRole %q can modify RBAC resources (roles/bindings), which may allow privilege escalation", cr.Name),
					Severity:    scanner.SeverityHigh,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("ClusterRole/%s", cr.Name),
					Remediation: "Review whether this role genuinely needs to create or modify RBAC resources. Apply the escalation verb restriction with 'escalate' and 'bind' permissions carefully.",
					Timestamp:   now,
				})
				break
			}
		}
	}

	for _, r := range roles {
		if strings.HasPrefix(r.Name, "system:") {
			continue
		}
		for _, rule := range r.Rules {
			if canEscalate(rule, sensitiveResources, escalatingVerbs) {
				findings = append(findings, scanner.Finding{
					ID:          "RBAC-005",
					Title:       "Potential privilege escalation in Role",
					Description: fmt.Sprintf("Role %s/%s can modify RBAC resources (roles/bindings)", r.Namespace, r.Name),
					Severity:    scanner.SeverityHigh,
					Status:      scanner.StatusFail,
					Category:    "rbac",
					Resource:    fmt.Sprintf("Role/%s/%s", r.Namespace, r.Name),
					Namespace:   r.Namespace,
					Remediation: "Review whether this role genuinely needs to create or modify RBAC resources.",
					Timestamp:   now,
				})
				break
			}
		}
	}

	return findings
}

// hasWildcard checks if a string slice contains the wildcard "*".
func hasWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

// canEscalate checks if a policy rule grants write access to RBAC resources.
func canEscalate(rule rbacv1.PolicyRule, sensitiveResources, escalatingVerbs map[string]bool) bool {
	hasSensitiveResource := false
	for _, res := range rule.Resources {
		if sensitiveResources[res] || res == "*" {
			hasSensitiveResource = true
			break
		}
	}
	if !hasSensitiveResource {
		return false
	}

	for _, verb := range rule.Verbs {
		if escalatingVerbs[verb] {
			return true
		}
	}
	return false
}
