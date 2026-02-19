package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/network"
	"github.com/kubecomply/kubecomply/pkg/policies"
	"github.com/kubecomply/kubecomply/pkg/pss"
	"github.com/kubecomply/kubecomply/pkg/rbac"
	"github.com/kubecomply/kubecomply/pkg/report"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

type scanFlags struct {
	format            string
	output            string
	scanType          string
	namespace         string
	severityThreshold string
	kubeconfig        string
	policyPaths       []string
	verbose           bool
}

func newScanCmd() *cobra.Command {
	flags := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run a compliance scan against the Kubernetes cluster",
		Long: `Run a compliance scan against the connected Kubernetes cluster.

Scan types:
  full      Run all checks (CIS, RBAC, Network, PSS)
  cis       CIS Kubernetes Benchmark checks via OPA policies
  rbac      RBAC security analysis
  network   NetworkPolicy coverage analysis
  pss       Pod Security Standards evaluation

Examples:
  kubecomply scan
  kubecomply scan --scan-type rbac --format json -o results.json
  kubecomply scan --scan-type full --severity-threshold high --namespace production
  kubecomply scan --kubeconfig ~/.kube/config --format html -o report.html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, flags)
		},
	}

	cmd.Flags().StringVarP(&flags.format, "format", "f", "table", "Output format: json, html, table")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&flags.scanType, "scan-type", "full", "Scan type: cis, rbac, network, pss, full")
	cmd.Flags().StringVarP(&flags.namespace, "namespace", "n", "", "Namespace to scan (default: all namespaces)")
	cmd.Flags().StringVar(&flags.severityThreshold, "severity-threshold", "info", "Minimum severity to report: critical, high, medium, low, info")
	cmd.Flags().StringVar(&flags.kubeconfig, "kubeconfig", "", "Path to kubeconfig file (default: $KUBECONFIG or ~/.kube/config)")
	cmd.Flags().StringSliceVar(&flags.policyPaths, "policy-path", nil, "Additional policy directory paths")
	cmd.Flags().BoolVarP(&flags.verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

func runScan(cmd *cobra.Command, flags *scanFlags) error {
	// Configure logging.
	logLevel := slog.LevelInfo
	if flags.verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Resolve kubeconfig.
	kubeconfig := flags.kubeconfig
	if kubeconfig == "" {
		kubeconfig = os.Getenv("KUBECONFIG")
	}
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			defaultPath := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(defaultPath); err == nil {
				kubeconfig = defaultPath
			}
		}
	}

	// Validate format.
	reportFormat, err := report.ParseFormat(flags.format)
	if err != nil {
		return err
	}

	// Validate severity threshold.
	threshold, err := scanner.ParseSeverity(flags.severityThreshold)
	if err != nil {
		return err
	}

	// Validate scan type.
	validScanTypes := map[string]bool{
		"full": true, "cis": true, "rbac": true, "network": true, "pss": true,
	}
	if !validScanTypes[flags.scanType] {
		return fmt.Errorf("invalid scan type: %q (valid: full, cis, rbac, network, pss)", flags.scanType)
	}

	// Create Kubernetes client.
	logger.Info("connecting to Kubernetes cluster", "kubeconfig", kubeconfig)
	k8sClient, err := k8s.NewClient(kubeconfig, logger)
	if err != nil {
		return fmt.Errorf("creating Kubernetes client: %w", err)
	}

	// Create policy engine.
	engine := policies.NewEngine(logger)

	// Load policies from additional paths.
	for _, path := range flags.policyPaths {
		if err := engine.LoadFromDirectory(path); err != nil {
			logger.Warn("failed to load policies from path", "path", path, "error", err)
		}
	}

	// Build scan config.
	config := &scanner.ScanConfig{
		ScanType:          flags.scanType,
		SeverityThreshold: threshold,
		PolicyPaths:       flags.policyPaths,
	}

	if flags.namespace != "" {
		config.Namespaces = []string{flags.namespace}
	}

	// Create and configure scanner with analyzers.
	ctx := cmd.Context()
	s := scanner.New(k8sClient, logger)
	s.SetPolicyEvaluator(engine)
	s.RegisterAnalyzer(rbac.NewAnalyzer(k8sClient, logger))
	s.RegisterAnalyzer(network.NewAnalyzer(k8sClient, logger))
	s.RegisterAnalyzer(pss.NewChecker(k8sClient, logger))

	// Run scan.
	result, err := s.Run(ctx, config)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report.
	reporter, err := report.NewReporter(reportFormat)
	if err != nil {
		return err
	}

	// Determine output writer.
	writer := cmd.OutOrStdout()
	if flags.output != "" {
		// Ensure the output directory exists.
		dir := filepath.Dir(flags.output)
		if dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}
		}

		f, err := os.Create(flags.output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		writer = f

		defer func() {
			fmt.Fprintf(os.Stderr, "Report written to %s\n", flags.output)
		}()
	}

	return reporter.Generate(writer, result)
}
