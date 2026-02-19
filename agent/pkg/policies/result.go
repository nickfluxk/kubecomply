// Package policies provides the OPA-based policy evaluation engine for
// evaluating Kubernetes resources against compliance policies.
package policies

import (
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

// CheckResult represents the outcome of evaluating a single policy check
// against a Kubernetes resource.
type CheckResult struct {
	// ID is the unique check identifier (e.g., "CIS-1.2.1").
	ID string `json:"id"`

	// Title is a human-readable name for the check.
	Title string `json:"title"`

	// Description explains what the check verifies.
	Description string `json:"description"`

	// Severity of the check.
	Severity scanner.Severity `json:"severity"`

	// Passed is true if the resource passed this check.
	Passed bool `json:"passed"`

	// Message provides details about why the check passed or failed.
	Message string `json:"message,omitempty"`

	// Resource is the affected Kubernetes resource identifier.
	Resource string `json:"resource,omitempty"`

	// Namespace of the affected resource.
	Namespace string `json:"namespace,omitempty"`

	// Remediation guidance for failed checks.
	Remediation string `json:"remediation,omitempty"`

	// Category of the policy (cis, nsa, rbac, pss, network).
	Category string `json:"category,omitempty"`
}

// ToFinding converts a CheckResult into a scanner.Finding.
func (cr *CheckResult) ToFinding() scanner.Finding {
	status := scanner.StatusPass
	if !cr.Passed {
		status = scanner.StatusFail
	}

	return scanner.Finding{
		ID:          cr.ID,
		Title:       cr.Title,
		Description: cr.Description,
		Severity:    cr.Severity,
		Status:      status,
		Category:    cr.Category,
		Resource:    cr.Resource,
		Namespace:   cr.Namespace,
		Remediation: cr.Remediation,
		Details: map[string]string{
			"message": cr.Message,
		},
	}
}

// PolicyMetadata describes a single policy definition.
type PolicyMetadata struct {
	// ID is the policy identifier.
	ID string `json:"id"`

	// Title is a short name for the policy.
	Title string `json:"title"`

	// Description explains the policy.
	Description string `json:"description"`

	// Category of the policy.
	Category string `json:"category"`

	// Severity is the default severity for findings from this policy.
	Severity scanner.Severity `json:"severity"`

	// Remediation is default remediation guidance.
	Remediation string `json:"remediation,omitempty"`

	// Source is the file path or identifier where the policy was loaded from.
	Source string `json:"source,omitempty"`
}

// PolicyBundle groups a set of related policies.
type PolicyBundle struct {
	// Name of the bundle (e.g., "CIS Kubernetes Benchmark v1.8").
	Name string `json:"name"`

	// Version of the benchmark or standard.
	Version string `json:"version,omitempty"`

	// Category of the bundle (cis, nsa, rbac, pss, network).
	Category string `json:"category"`

	// Policies in this bundle.
	Policies []PolicyMetadata `json:"policies"`

	// RegoModules maps module names to their Rego source code.
	RegoModules map[string]string `json:"regoModules,omitempty"`
}

// PolicyEvalInput is the input structure passed to OPA for evaluation.
type PolicyEvalInput struct {
	// Resource is the Kubernetes resource being evaluated.
	Resource interface{} `json:"resource"`

	// Namespace is the namespace context.
	Namespace string `json:"namespace,omitempty"`

	// Parameters are additional policy parameters.
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// PolicyEvalOutput is the expected output structure from OPA evaluation.
type PolicyEvalOutput struct {
	// Violations is a list of policy violations found.
	Violations []Violation `json:"violations,omitempty"`
}

// Violation represents a single policy violation returned by OPA.
type Violation struct {
	// ID is the check identifier.
	ID string `json:"id,omitempty"`

	// Title of the violated check.
	Title string `json:"title,omitempty"`

	// Message describes the violation.
	Message string `json:"msg"`

	// Severity of the violation.
	Severity string `json:"severity,omitempty"`

	// Resource that violated the policy.
	Resource string `json:"resource,omitempty"`

	// Namespace of the violating resource.
	Namespace string `json:"namespace,omitempty"`

	// Remediation guidance.
	Remediation string `json:"remediation,omitempty"`
}
