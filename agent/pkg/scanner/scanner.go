package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Analyzer is the interface implemented by all compliance analyzers
// (RBAC, Network, PSS, etc.). The scanner orchestrates them.
type Analyzer interface {
	// Name returns the analyzer name (e.g., "rbac", "network", "pss").
	Name() string

	// Analyze runs the analysis and returns findings.
	Analyze(ctx context.Context, namespaces []string) ([]Finding, error)
}

// PolicyEvaluator is the interface for OPA policy evaluation.
type PolicyEvaluator interface {
	// ModuleCount returns the number of loaded policy modules.
	ModuleCount() int

	// LoadFromDirectory loads policy modules from a filesystem directory.
	LoadFromDirectory(dir string) error

	// EvaluateResource evaluates a single resource against loaded policies.
	EvaluateResource(ctx context.Context, resource interface{}, namespace string, query string) ([]PolicyCheckResult, error)
}

// PolicyCheckResult represents a single OPA policy check result.
// This mirrors policies.CheckResult but avoids the circular import.
type PolicyCheckResult struct {
	ID          string
	Title       string
	Description string
	Severity    Severity
	Passed      bool
	Message     string
	Resource    string
	Namespace   string
	Remediation string
	Category    string
}

// ToFinding converts a PolicyCheckResult into a Finding.
func (cr *PolicyCheckResult) ToFinding() Finding {
	status := StatusPass
	if !cr.Passed {
		status = StatusFail
	}
	return Finding{
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

// ResourceLister provides read-only access to Kubernetes resources for the
// scanner. This avoids importing the k8s package directly.
type ResourceLister interface {
	ClusterName() string
	NamespacesForScan(ctx context.Context, requested []string, includeSystem bool) ([]string, error)
	ListPodsJSON(ctx context.Context, namespace string) ([]interface{}, error)
	ListDeploymentsJSON(ctx context.Context, namespace string) ([]interface{}, error)
}

// Scanner orchestrates compliance scanning by coordinating policy evaluation
// and registered analyzers.
type Scanner struct {
	lister          ResourceLister
	policyEvaluator PolicyEvaluator
	analyzers       map[string]Analyzer
	logger          *slog.Logger
}

// New creates a new Scanner.
func New(lister ResourceLister, logger *slog.Logger) *Scanner {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scanner{
		lister:    lister,
		analyzers: make(map[string]Analyzer),
		logger:    logger,
	}
}

// SetPolicyEvaluator sets the OPA policy evaluator.
func (s *Scanner) SetPolicyEvaluator(pe PolicyEvaluator) {
	s.policyEvaluator = pe
}

// RegisterAnalyzer adds an analyzer to the scanner.
func (s *Scanner) RegisterAnalyzer(a Analyzer) {
	s.analyzers[a.Name()] = a
}

// Run executes a compliance scan based on the provided configuration.
func (s *Scanner) Run(ctx context.Context, config *ScanConfig) (*ScanResult, error) {
	startTime := time.Now()
	scanID := fmt.Sprintf("scan-%d", startTime.UnixMilli())

	s.logger.Info("starting compliance scan",
		"scanType", config.ScanType,
		"namespaces", config.Namespaces,
		"threshold", config.SeverityThreshold,
	)

	result := &ScanResult{
		ID:          scanID,
		ScanType:    config.ScanType,
		StartTime:   startTime,
		ClusterName: s.lister.ClusterName(),
	}

	// Resolve target namespaces.
	namespaces, err := s.lister.NamespacesForScan(ctx, config.Namespaces, false)
	if err != nil {
		return nil, fmt.Errorf("resolving namespaces: %w", err)
	}
	result.Namespaces = namespaces
	s.logger.Info("scanning namespaces", "count", len(namespaces), "namespaces", namespaces)

	// Load additional policy paths.
	if s.policyEvaluator != nil {
		for _, path := range config.PolicyPaths {
			if err := s.policyEvaluator.LoadFromDirectory(path); err != nil {
				s.logger.Warn("failed to load policy directory", "path", path, "error", err)
			}
		}
	}

	// Run scans based on type.
	switch config.ScanType {
	case "full":
		s.runOPAPolicies(ctx, result, namespaces)
		s.runAnalyzers(ctx, result, namespaces, "rbac", "network", "pss")

	case "cis":
		s.runOPAPolicies(ctx, result, namespaces)

	case "rbac":
		if err := s.runAnalyzer(ctx, result, namespaces, "rbac"); err != nil {
			return nil, fmt.Errorf("RBAC analysis: %w", err)
		}

	case "network":
		if err := s.runAnalyzer(ctx, result, namespaces, "network"); err != nil {
			return nil, fmt.Errorf("network analysis: %w", err)
		}

	case "pss":
		if err := s.runAnalyzer(ctx, result, namespaces, "pss"); err != nil {
			return nil, fmt.Errorf("PSS check: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown scan type: %q (valid: full, cis, rbac, network, pss)", config.ScanType)
	}

	// Finalize results.
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	// Stamp all findings that lack a timestamp.
	for i := range result.Findings {
		if result.Findings[i].Timestamp.IsZero() {
			result.Findings[i].Timestamp = result.EndTime
		}
	}

	result.ComputeSummary()

	// Apply severity threshold filter.
	if config.SeverityThreshold != "" {
		result = result.FilterByThreshold(config.SeverityThreshold)
	}

	s.logger.Info("compliance scan complete",
		"scanID", result.ID,
		"duration", result.Duration,
		"totalChecks", result.Summary.TotalChecks,
		"passed", result.Summary.PassedChecks,
		"failed", result.Summary.FailedChecks,
		"score", fmt.Sprintf("%.1f%%", result.Summary.Score),
	)

	return result, nil
}

// runOPAPolicies evaluates loaded OPA/Rego policies against cluster resources.
func (s *Scanner) runOPAPolicies(ctx context.Context, result *ScanResult, namespaces []string) {
	if s.policyEvaluator == nil || s.policyEvaluator.ModuleCount() == 0 {
		s.logger.Info("no OPA policy modules loaded, skipping policy evaluation")
		return
	}

	s.logger.Info("running OPA policy evaluation", "modules", s.policyEvaluator.ModuleCount())

	for _, ns := range namespaces {
		// Evaluate pods.
		pods, err := s.lister.ListPodsJSON(ctx, ns)
		if err != nil {
			s.logger.Warn("failed to list pods for policy evaluation", "namespace", ns, "error", err)
			continue
		}

		for i, pod := range pods {
			checks, err := s.policyEvaluator.EvaluateResource(ctx, pod, ns, "data.compliance.violations")
			if err != nil {
				s.logger.Warn("OPA evaluation failed for pod", "index", i, "namespace", ns, "error", err)
				continue
			}
			for _, check := range checks {
				if check.Resource == "" {
					check.Resource = fmt.Sprintf("Pod/%s/pod-%d", ns, i)
				}
				if check.Namespace == "" {
					check.Namespace = ns
				}
				result.Findings = append(result.Findings, check.ToFinding())
			}
		}

		// Evaluate deployments.
		deployments, err := s.lister.ListDeploymentsJSON(ctx, ns)
		if err != nil {
			s.logger.Warn("failed to list deployments for policy evaluation", "namespace", ns, "error", err)
			continue
		}

		for i, deploy := range deployments {
			checks, err := s.policyEvaluator.EvaluateResource(ctx, deploy, ns, "data.compliance.violations")
			if err != nil {
				s.logger.Warn("OPA evaluation failed for deployment", "index", i, "namespace", ns, "error", err)
				continue
			}
			for _, check := range checks {
				if check.Resource == "" {
					check.Resource = fmt.Sprintf("Deployment/%s/deploy-%d", ns, i)
				}
				if check.Namespace == "" {
					check.Namespace = ns
				}
				result.Findings = append(result.Findings, check.ToFinding())
			}
		}
	}
}

// runAnalyzer runs a single named analyzer.
func (s *Scanner) runAnalyzer(ctx context.Context, result *ScanResult, namespaces []string, name string) error {
	analyzer, ok := s.analyzers[name]
	if !ok {
		s.logger.Warn("analyzer not registered", "name", name)
		return nil
	}

	s.logger.Info("running analyzer", "name", name)
	findings, err := analyzer.Analyze(ctx, namespaces)
	if err != nil {
		return err
	}

	result.Findings = append(result.Findings, findings...)
	return nil
}

// runAnalyzers runs multiple named analyzers, logging errors without failing.
func (s *Scanner) runAnalyzers(ctx context.Context, result *ScanResult, namespaces []string, names ...string) {
	for _, name := range names {
		if err := s.runAnalyzer(ctx, result, namespaces, name); err != nil {
			s.logger.Error("analyzer failed", "name", name, "error", err)
		}
	}
}
