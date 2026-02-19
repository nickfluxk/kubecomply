// Package network provides analysis of Kubernetes NetworkPolicy configurations
// to identify namespaces and workloads lacking proper network segmentation.
package network

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"

	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// Analyzer evaluates NetworkPolicy coverage across the cluster.
// It implements the scanner.Analyzer interface.
type Analyzer struct {
	client *k8s.Client
	logger *slog.Logger
}

// Name returns the analyzer name.
func (a *Analyzer) Name() string { return "network" }

// NewAnalyzer creates a new NetworkPolicy analyzer.
func NewAnalyzer(client *k8s.Client, logger *slog.Logger) *Analyzer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Analyzer{
		client: client,
		logger: logger,
	}
}

// namespacePolicyInfo tracks policy coverage for a single namespace.
type namespacePolicyInfo struct {
	hasIngress       bool
	hasEgress        bool
	policyCount      int
	defaultDenyAll   bool
	defaultDenyIngr  bool
	defaultDenyEgr   bool
}

// Analyze runs all NetworkPolicy checks and returns findings.
func (a *Analyzer) Analyze(ctx context.Context, namespaces []string) ([]scanner.Finding, error) {
	a.logger.Info("starting network policy analysis")

	now := time.Now()
	var findings []scanner.Finding

	// Get all namespaces with their labels.
	allNamespaces, err := a.client.ListNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing namespaces: %w", err)
	}

	// Build a set of namespaces to scan.
	scanNS := make(map[string]bool)
	if len(namespaces) > 0 {
		for _, ns := range namespaces {
			scanNS[ns] = true
		}
	} else {
		for _, ns := range allNamespaces {
			scanNS[ns.Name] = true
		}
	}

	// Gather all network policies across target namespaces.
	nsPolicies := make(map[string][]networkingv1.NetworkPolicy)
	for ns := range scanNS {
		policies, err := a.client.ListNetworkPolicies(ctx, ns)
		if err != nil {
			a.logger.Warn("failed to list network policies", "namespace", ns, "error", err)
			continue
		}
		nsPolicies[ns] = policies
	}

	// Check 1: Namespace coverage (does each namespace have at least one NetworkPolicy?).
	findings = append(findings, a.checkNamespaceCoverage(nsPolicies, scanNS, now)...)

	// Check 2: Default deny policies.
	findings = append(findings, a.checkDefaultDenyPolicies(nsPolicies, now)...)

	// Check 3: Ingress and egress coverage per namespace.
	findings = append(findings, a.checkIngressEgressCoverage(nsPolicies, now)...)

	// Check 4: Open NodePort and LoadBalancer services.
	findings = append(findings, a.checkExposedServices(ctx, scanNS, now)...)

	a.logger.Info("network policy analysis complete", "findings", len(findings))
	return findings, nil
}

// checkNamespaceCoverage identifies namespaces with no NetworkPolicies.
func (a *Analyzer) checkNamespaceCoverage(
	nsPolicies map[string][]networkingv1.NetworkPolicy,
	scanNS map[string]bool,
	now time.Time,
) []scanner.Finding {
	var findings []scanner.Finding

	// System namespaces are handled differently.
	systemNS := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	coveredCount := 0
	totalCount := 0

	for ns := range scanNS {
		if systemNS[ns] {
			continue
		}
		totalCount++

		policies := nsPolicies[ns]
		if len(policies) == 0 {
			findings = append(findings, scanner.Finding{
				ID:          "NET-001",
				Title:       "Namespace has no NetworkPolicies",
				Description: fmt.Sprintf("Namespace %q has no NetworkPolicies, meaning all pods accept unrestricted traffic", ns),
				Severity:    scanner.SeverityHigh,
				Status:      scanner.StatusFail,
				Category:    "network",
				Resource:    fmt.Sprintf("Namespace/%s", ns),
				Namespace:   ns,
				Remediation: "Create NetworkPolicies to restrict ingress and egress traffic. Start with a default-deny policy and add explicit allow rules.",
				Timestamp:   now,
			})
		} else {
			coveredCount++
		}
	}

	// Overall coverage finding.
	if totalCount > 0 {
		coveragePct := float64(coveredCount) / float64(totalCount) * 100.0
		status := scanner.StatusPass
		severity := scanner.SeverityInfo
		if coveragePct < 50 {
			status = scanner.StatusFail
			severity = scanner.SeverityHigh
		} else if coveragePct < 100 {
			status = scanner.StatusWarning
			severity = scanner.SeverityMedium
		}

		findings = append(findings, scanner.Finding{
			ID:          "NET-002",
			Title:       "NetworkPolicy namespace coverage",
			Description: fmt.Sprintf("%.0f%% of namespaces (%d/%d) have at least one NetworkPolicy", coveragePct, coveredCount, totalCount),
			Severity:    severity,
			Status:      status,
			Category:    "network",
			Details: map[string]string{
				"covered":  fmt.Sprintf("%d", coveredCount),
				"total":    fmt.Sprintf("%d", totalCount),
				"coverage": fmt.Sprintf("%.1f%%", coveragePct),
			},
			Timestamp: now,
		})
	}

	return findings
}

// checkDefaultDenyPolicies checks if namespaces have default-deny NetworkPolicies.
func (a *Analyzer) checkDefaultDenyPolicies(
	nsPolicies map[string][]networkingv1.NetworkPolicy,
	now time.Time,
) []scanner.Finding {
	var findings []scanner.Finding

	for ns, policies := range nsPolicies {
		if len(policies) == 0 {
			continue
		}

		info := analyzeNamespacePolicies(policies)

		if !info.defaultDenyIngr {
			findings = append(findings, scanner.Finding{
				ID:          "NET-003",
				Title:       "Missing default-deny ingress policy",
				Description: fmt.Sprintf("Namespace %q lacks a default-deny ingress NetworkPolicy; pods without explicit policies accept all ingress", ns),
				Severity:    scanner.SeverityMedium,
				Status:      scanner.StatusFail,
				Category:    "network",
				Resource:    fmt.Sprintf("Namespace/%s", ns),
				Namespace:   ns,
				Remediation: "Create a NetworkPolicy with podSelector: {} and policyTypes: [Ingress] with no ingress rules to deny all ingress by default.",
				Timestamp:   now,
			})
		}

		if !info.defaultDenyEgr {
			findings = append(findings, scanner.Finding{
				ID:          "NET-004",
				Title:       "Missing default-deny egress policy",
				Description: fmt.Sprintf("Namespace %q lacks a default-deny egress NetworkPolicy; pods without explicit policies can send traffic anywhere", ns),
				Severity:    scanner.SeverityMedium,
				Status:      scanner.StatusWarning,
				Category:    "network",
				Resource:    fmt.Sprintf("Namespace/%s", ns),
				Namespace:   ns,
				Remediation: "Create a NetworkPolicy with podSelector: {} and policyTypes: [Egress] with no egress rules to deny all egress by default.",
				Timestamp:   now,
			})
		}
	}

	return findings
}

// checkIngressEgressCoverage identifies namespaces with policies that
// only cover ingress or only cover egress.
func (a *Analyzer) checkIngressEgressCoverage(
	nsPolicies map[string][]networkingv1.NetworkPolicy,
	now time.Time,
) []scanner.Finding {
	var findings []scanner.Finding

	for ns, policies := range nsPolicies {
		if len(policies) == 0 {
			continue
		}

		info := analyzeNamespacePolicies(policies)

		if info.hasIngress && !info.hasEgress {
			findings = append(findings, scanner.Finding{
				ID:          "NET-005",
				Title:       "Namespace has ingress policies but no egress policies",
				Description: fmt.Sprintf("Namespace %q has %d NetworkPolicies covering ingress but none covering egress", ns, info.policyCount),
				Severity:    scanner.SeverityLow,
				Status:      scanner.StatusWarning,
				Category:    "network",
				Resource:    fmt.Sprintf("Namespace/%s", ns),
				Namespace:   ns,
				Remediation: "Add egress NetworkPolicies to control outbound traffic and prevent data exfiltration.",
				Timestamp:   now,
			})
		}
	}

	return findings
}

// checkExposedServices identifies NodePort and LoadBalancer services.
func (a *Analyzer) checkExposedServices(ctx context.Context, scanNS map[string]bool, now time.Time) []scanner.Finding {
	var findings []scanner.Finding

	for ns := range scanNS {
		services, err := a.client.ListServices(ctx, ns)
		if err != nil {
			a.logger.Warn("failed to list services", "namespace", ns, "error", err)
			continue
		}

		for _, svc := range services {
			switch svc.Spec.Type {
			case corev1.ServiceTypeNodePort:
				for _, port := range svc.Spec.Ports {
					findings = append(findings, scanner.Finding{
						ID:          "NET-006",
						Title:       "NodePort service detected",
						Description: fmt.Sprintf("Service %s/%s exposes NodePort %d (target port %s)", svc.Namespace, svc.Name, port.NodePort, port.TargetPort.String()),
						Severity:    scanner.SeverityMedium,
						Status:      scanner.StatusWarning,
						Category:    "network",
						Resource:    fmt.Sprintf("Service/%s/%s", svc.Namespace, svc.Name),
						Namespace:   svc.Namespace,
						Remediation: "Consider using a LoadBalancer or Ingress controller instead of NodePort to avoid exposing ports on all cluster nodes.",
						Details: map[string]string{
							"node_port":   fmt.Sprintf("%d", port.NodePort),
							"target_port": port.TargetPort.String(),
							"protocol":    string(port.Protocol),
						},
						Timestamp: now,
					})
				}

			case corev1.ServiceTypeLoadBalancer:
				findings = append(findings, scanner.Finding{
					ID:          "NET-007",
					Title:       "LoadBalancer service detected",
					Description: fmt.Sprintf("Service %s/%s is exposed via LoadBalancer", svc.Namespace, svc.Name),
					Severity:    scanner.SeverityLow,
					Status:      scanner.StatusWarning,
					Category:    "network",
					Resource:    fmt.Sprintf("Service/%s/%s", svc.Namespace, svc.Name),
					Namespace:   svc.Namespace,
					Remediation: "Verify that the LoadBalancer has appropriate security group rules and is not publicly accessible unless intended.",
					Timestamp:   now,
				})
			}
		}
	}

	return findings
}

// analyzeNamespacePolicies examines all policies in a namespace and determines
// what types of traffic control are present.
func analyzeNamespacePolicies(policies []networkingv1.NetworkPolicy) namespacePolicyInfo {
	info := namespacePolicyInfo{
		policyCount: len(policies),
	}

	for _, policy := range policies {
		isSelectAll := len(policy.Spec.PodSelector.MatchLabels) == 0 &&
			len(policy.Spec.PodSelector.MatchExpressions) == 0

		for _, pt := range policy.Spec.PolicyTypes {
			switch pt {
			case networkingv1.PolicyTypeIngress:
				info.hasIngress = true
				if isSelectAll && len(policy.Spec.Ingress) == 0 {
					info.defaultDenyIngr = true
				}
			case networkingv1.PolicyTypeEgress:
				info.hasEgress = true
				if isSelectAll && len(policy.Spec.Egress) == 0 {
					info.defaultDenyEgr = true
				}
			}
		}

		if isSelectAll && info.defaultDenyIngr && info.defaultDenyEgr {
			info.defaultDenyAll = true
		}
	}

	return info
}
