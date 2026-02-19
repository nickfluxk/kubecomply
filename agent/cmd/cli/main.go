// Package main is the entrypoint for the KubeComply CLI tool.
// It provides commands for running compliance scans, analyzing RBAC and
// network policies, generating reports, and managing the tool.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/network"
	"github.com/kubecomply/kubecomply/pkg/rbac"
	"github.com/kubecomply/kubecomply/pkg/report"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "kubecomply",
		Short: "KubeComply - Kubernetes Compliance Scanner",
		Long: `KubeComply is a comprehensive Kubernetes compliance scanner that evaluates
your cluster against CIS benchmarks, RBAC best practices, NetworkPolicy
coverage, and Pod Security Standards.

Use the scan command for a full compliance assessment, or analyze specific
areas with the analyze subcommands.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newVersionCmd())

	return rootCmd
}

// newAnalyzeCmd creates the `analyze` command with subcommands for focused analysis.
func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Run focused analysis on specific areas",
		Long:  "Analyze specific aspects of cluster compliance. Use subcommands for RBAC or network analysis.",
	}

	cmd.AddCommand(newAnalyzeRBACCmd())
	cmd.AddCommand(newAnalyzeNetworkCmd())

	return cmd
}

func newAnalyzeRBACCmd() *cobra.Command {
	var (
		kubeconfig string
		namespace  string
		format     string
		output     string
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "rbac",
		Short: "Analyze RBAC configuration for security issues",
		Long: `Analyze Kubernetes RBAC configuration to identify security risks including:
  - Non-default cluster-admin bindings
  - Wildcard permissions in roles
  - Unused roles and ClusterRoles
  - Bindings using the default ServiceAccount
  - Potential privilege escalation paths`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logLevel := slog.LevelInfo
			if verbose {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			k8sClient, err := k8s.NewClient(resolveKubeconfig(kubeconfig), logger)
			if err != nil {
				return fmt.Errorf("creating Kubernetes client: %w", err)
			}

			ctx := cmd.Context()
			var namespaces []string
			if namespace != "" {
				namespaces = []string{namespace}
			} else {
				namespaces, err = k8sClient.NamespacesForScan(ctx, nil, false)
				if err != nil {
					return fmt.Errorf("resolving namespaces: %w", err)
				}
			}

			analyzer := rbac.NewAnalyzer(k8sClient, logger)
			findings, err := analyzer.Analyze(ctx, namespaces)
			if err != nil {
				return fmt.Errorf("RBAC analysis failed: %w", err)
			}

			return outputFindings(cmd, findings, k8sClient.ClusterName(), "rbac", format, output)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to analyze (default: all)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: json, html, table")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

func newAnalyzeNetworkCmd() *cobra.Command {
	var (
		kubeconfig string
		namespace  string
		format     string
		output     string
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "network",
		Short: "Analyze NetworkPolicy coverage",
		Long: `Analyze Kubernetes NetworkPolicy coverage to identify:
  - Namespaces with no NetworkPolicies
  - Missing default-deny policies
  - Incomplete ingress/egress coverage
  - Exposed NodePort and LoadBalancer services`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logLevel := slog.LevelInfo
			if verbose {
				logLevel = slog.LevelDebug
			}
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

			k8sClient, err := k8s.NewClient(resolveKubeconfig(kubeconfig), logger)
			if err != nil {
				return fmt.Errorf("creating Kubernetes client: %w", err)
			}

			ctx := cmd.Context()
			var namespaces []string
			if namespace != "" {
				namespaces = []string{namespace}
			} else {
				namespaces, err = k8sClient.NamespacesForScan(ctx, nil, false)
				if err != nil {
					return fmt.Errorf("resolving namespaces: %w", err)
				}
			}

			analyzer := network.NewAnalyzer(k8sClient, logger)
			findings, err := analyzer.Analyze(ctx, namespaces)
			if err != nil {
				return fmt.Errorf("network analysis failed: %w", err)
			}

			return outputFindings(cmd, findings, k8sClient.ClusterName(), "network", format, output)
		},
	}

	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to analyze (default: all)")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: json, html, table")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	return cmd
}

// newReportCmd creates the `report` command for generating reports from
// previously saved scan results.
func newReportCmd() *cobra.Command {
	var (
		inputFile string
		format    string
		output    string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report from scan results",
		Long:  "Generate a compliance report in the specified format from a previously saved JSON scan result.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if inputFile == "" {
				return fmt.Errorf("--input is required: provide a path to a JSON scan result file")
			}

			data, err := os.ReadFile(inputFile)
			if err != nil {
				return fmt.Errorf("reading input file: %w", err)
			}

			var result scanner.ScanResult
			if err := json.Unmarshal(data, &result); err != nil {
				return fmt.Errorf("parsing scan result JSON: %w", err)
			}

			reportFormat, err := report.ParseFormat(format)
			if err != nil {
				return err
			}

			reporter, err := report.NewReporter(reportFormat)
			if err != nil {
				return err
			}

			writer := cmd.OutOrStdout()
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("creating output file: %w", err)
				}
				defer f.Close()
				writer = f
			}

			return reporter.Generate(writer, &result)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input JSON scan result file")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: json, html, table")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path")

	return cmd
}

// Helper functions.

func resolveKubeconfig(kubeconfig string) string {
	if kubeconfig != "" {
		return kubeconfig
	}
	if env := os.Getenv("KUBECONFIG"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := home + "/.kube/config"
	if _, err := os.Stat(path); err == nil {
		return path
	}
	return ""
}

func outputFindings(cmd *cobra.Command, findings []scanner.Finding, clusterName, scanType, format, output string) error {
	// Build a ScanResult from the findings.
	result := &scanner.ScanResult{
		ScanType:    scanType,
		ClusterName: clusterName,
		Findings:    findings,
	}
	result.ComputeSummary()

	reportFormat, err := report.ParseFormat(format)
	if err != nil {
		return err
	}

	reporter, err := report.NewReporter(reportFormat)
	if err != nil {
		return err
	}

	writer := cmd.OutOrStdout()
	if output != "" {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		writer = f
	}

	return reporter.Generate(writer, result)
}
