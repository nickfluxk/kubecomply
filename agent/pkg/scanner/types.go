// Package scanner provides the core compliance scanning engine and shared types
// for the KubeComply agent.
package scanner

import (
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity level of a compliance finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityRank returns the numeric rank of a severity for comparison.
// Higher rank means more severe.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ParseSeverity converts a string to a Severity, returning an error for invalid values.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(strings.ToLower(s)) {
	case SeverityCritical:
		return SeverityCritical, nil
	case SeverityHigh:
		return SeverityHigh, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityInfo:
		return SeverityInfo, nil
	default:
		return "", fmt.Errorf("invalid severity: %q (valid: critical, high, medium, low, info)", s)
	}
}

// MeetsThreshold returns true if the severity meets or exceeds the threshold.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	return SeverityRank(s) >= SeverityRank(threshold)
}

// FindingStatus represents the pass/fail status of a compliance check.
type FindingStatus string

const (
	StatusPass    FindingStatus = "PASS"
	StatusFail    FindingStatus = "FAIL"
	StatusWarning FindingStatus = "WARNING"
	StatusError   FindingStatus = "ERROR"
	StatusSkipped FindingStatus = "SKIPPED"
)

// Finding represents a single compliance check result.
type Finding struct {
	// ID is a unique identifier for the check (e.g., "CIS-1.2.3").
	ID string `json:"id"`

	// Title is a short description of the check.
	Title string `json:"title"`

	// Description provides detailed information about the check.
	Description string `json:"description"`

	// Severity indicates the importance of the finding.
	Severity Severity `json:"severity"`

	// Status indicates whether the check passed or failed.
	Status FindingStatus `json:"status"`

	// Category groups the finding (cis, rbac, network, pss).
	Category string `json:"category"`

	// Resource is the Kubernetes resource this finding pertains to.
	Resource string `json:"resource,omitempty"`

	// Namespace is the namespace of the affected resource.
	Namespace string `json:"namespace,omitempty"`

	// Remediation provides guidance on how to fix the issue.
	Remediation string `json:"remediation,omitempty"`

	// Details contains additional context about the finding.
	Details map[string]string `json:"details,omitempty"`

	// Timestamp is when the finding was generated.
	Timestamp time.Time `json:"timestamp"`
}

// ScanSummary aggregates scan statistics.
type ScanSummary struct {
	TotalChecks  int     `json:"totalChecks"`
	PassedChecks int     `json:"passedChecks"`
	FailedChecks int     `json:"failedChecks"`
	WarningCount int     `json:"warningCount"`
	ErrorCount   int     `json:"errorCount"`
	SkippedCount int     `json:"skippedCount"`
	Score        float64 `json:"score"`

	// FindingsBySeverity counts findings by severity level.
	FindingsBySeverity map[Severity]int `json:"findingsBySeverity"`
}

// ScanResult holds the complete output of a compliance scan.
type ScanResult struct {
	// ID is a unique identifier for this scan run.
	ID string `json:"id"`

	// ScanType is the type of scan that was performed.
	ScanType string `json:"scanType"`

	// StartTime is when the scan began.
	StartTime time.Time `json:"startTime"`

	// EndTime is when the scan completed.
	EndTime time.Time `json:"endTime"`

	// Duration is the wall-clock time for the scan.
	Duration time.Duration `json:"duration"`

	// ClusterName is the name of the scanned cluster.
	ClusterName string `json:"clusterName,omitempty"`

	// Namespaces that were scanned.
	Namespaces []string `json:"namespaces,omitempty"`

	// Findings contains all individual check results.
	Findings []Finding `json:"findings"`

	// Summary provides aggregated statistics.
	Summary ScanSummary `json:"summary"`
}

// ScanConfig controls how a scan is executed.
type ScanConfig struct {
	// ScanType selects which checks to run: cis, rbac, network, pss, full.
	ScanType string `json:"scanType"`

	// Namespaces to scope the scan. Empty means all namespaces.
	Namespaces []string `json:"namespaces,omitempty"`

	// SeverityThreshold filters findings at or above this level.
	SeverityThreshold Severity `json:"severityThreshold"`

	// PolicyPaths lists additional directories containing Rego policies.
	PolicyPaths []string `json:"policyPaths,omitempty"`

	// Kubeconfig is the path to the kubeconfig file. Empty means in-cluster.
	Kubeconfig string `json:"kubeconfig,omitempty"`

	// SaaSEndpoint is the SaaS API base URL for uploading results.
	SaaSEndpoint string `json:"saasEndpoint,omitempty"`

	// SaaSToken is the authentication token for SaaS API.
	SaaSToken string `json:"saasToken,omitempty"`
}

// ComputeSummary recalculates the Summary field from the Findings slice.
func (r *ScanResult) ComputeSummary() {
	summary := ScanSummary{
		FindingsBySeverity: make(map[Severity]int),
	}

	for _, f := range r.Findings {
		summary.TotalChecks++
		switch f.Status {
		case StatusPass:
			summary.PassedChecks++
		case StatusFail:
			summary.FailedChecks++
			summary.FindingsBySeverity[f.Severity]++
		case StatusWarning:
			summary.WarningCount++
			summary.FindingsBySeverity[f.Severity]++
		case StatusError:
			summary.ErrorCount++
		case StatusSkipped:
			summary.SkippedCount++
		}
	}

	// Score = percentage of passed checks out of actionable checks (pass + fail).
	actionable := summary.PassedChecks + summary.FailedChecks
	if actionable > 0 {
		summary.Score = float64(summary.PassedChecks) / float64(actionable) * 100.0
	}

	r.Summary = summary
}

// FilterByThreshold returns a new ScanResult containing only findings at or
// above the given severity threshold. Pass findings are always retained.
func (r *ScanResult) FilterByThreshold(threshold Severity) *ScanResult {
	filtered := &ScanResult{
		ID:          r.ID,
		ScanType:    r.ScanType,
		StartTime:   r.StartTime,
		EndTime:     r.EndTime,
		Duration:    r.Duration,
		ClusterName: r.ClusterName,
		Namespaces:  r.Namespaces,
	}

	for _, f := range r.Findings {
		// Always include pass findings and findings meeting the threshold.
		if f.Status == StatusPass || f.Severity.MeetsThreshold(threshold) {
			filtered.Findings = append(filtered.Findings, f)
		}
	}

	filtered.ComputeSummary()
	return filtered
}
