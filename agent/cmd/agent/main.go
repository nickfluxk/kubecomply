// Package main is the entrypoint for the KubeComply operator agent.
// It sets up the controller-runtime manager, registers the ComplianceScan
// controller, and starts the metrics server and health probes.
package main

import (
	"flag"
	"log/slog"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/kubecomply/kubecomply/api/v1alpha1"
	"github.com/kubecomply/kubecomply/internal/controller"
	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/policies"
	"github.com/kubecomply/kubecomply/pkg/saas"
)

// Build-time variables set by ldflags.
var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		healthProbeAddr      string
		enableLeaderElection bool
		policyDir            string
		saasEndpoint         string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&healthProbeAddr, "health-probe-bind-address", ":8081", "The address the health probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for controller manager, ensuring only one active controller.")
	flag.StringVar(&policyDir, "policy-dir", "", "Directory containing OPA/Rego policy files.")
	flag.StringVar(&saasEndpoint, "saas-endpoint", "", "KubeComply SaaS API endpoint (empty disables SaaS integration).")
	flag.Parse()

	// Configure structured logging.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting KubeComply agent",
		"version", version,
		"gitCommit", gitCommit,
		"buildDate", buildDate,
	)

	// Create the controller manager.
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthProbeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "kubecomply-agent-leader",
	})
	if err != nil {
		logger.Error("unable to create manager", "error", err)
		os.Exit(1)
	}

	// Create the Kubernetes client wrapper for read-only operations.
	k8sClient, err := k8s.NewClient("", logger)
	if err != nil {
		logger.Error("unable to create k8s client", "error", err)
		os.Exit(1)
	}

	// Initialize the policy engine.
	policyEngine := policies.NewEngine(logger)
	if policyDir != "" {
		if err := policyEngine.LoadFromDirectory(policyDir); err != nil {
			logger.Error("failed to load policies from directory", "dir", policyDir, "error", err)
			os.Exit(1)
		}
		logger.Info("loaded policy modules", "count", policyEngine.ModuleCount(), "dir", policyDir)
	}

	// Initialize SaaS client if endpoint is configured.
	var saasClient *saas.Client
	if saasEndpoint != "" {
		saasClient = saas.NewClient(saasEndpoint, logger)
		logger.Info("SaaS integration enabled", "endpoint", saasEndpoint)
	}

	// Register the ComplianceScan reconciler.
	reconciler := &controller.ComplianceScanReconciler{
		Client:       mgr.GetClient(),
		Scheme:       mgr.GetScheme(),
		K8sClient:    k8sClient,
		PolicyEngine: policyEngine,
		SaaSClient:   saasClient,
		Logger:       logger,
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		logger.Error("unable to create controller", "controller", "ComplianceScan", "error", err)
		os.Exit(1)
	}

	// Register health and readiness probes.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error("unable to set up health check", "error", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error("unable to set up readiness check", "error", err)
		os.Exit(1)
	}

	logger.Info("starting manager",
		"metricsAddr", metricsAddr,
		"healthProbeAddr", healthProbeAddr,
		"leaderElection", enableLeaderElection,
	)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("manager exited with error", "error", err)
		os.Exit(1)
	}
}
