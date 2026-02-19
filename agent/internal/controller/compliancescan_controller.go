// Package controller implements the Kubernetes controller for ComplianceScan CRDs.
package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	v1alpha1 "github.com/kubecomply/kubecomply/api/v1alpha1"
	"github.com/kubecomply/kubecomply/pkg/k8s"
	"github.com/kubecomply/kubecomply/pkg/metrics"
	"github.com/kubecomply/kubecomply/pkg/network"
	"github.com/kubecomply/kubecomply/pkg/policies"
	"github.com/kubecomply/kubecomply/pkg/pss"
	"github.com/kubecomply/kubecomply/pkg/rbac"
	"github.com/kubecomply/kubecomply/pkg/saas"
	"github.com/kubecomply/kubecomply/pkg/scanner"
)

const (
	finalizerName = "compliance.kubecomply.io/finalizer"
)

// ComplianceScanReconciler reconciles ComplianceScan objects.
type ComplianceScanReconciler struct {
	client.Client
	Scheme       *runtime.Scheme
	K8sClient    *k8s.Client
	PolicyEngine *policies.Engine
	SaaSClient   *saas.Client
	Logger       *slog.Logger
}

// +kubebuilder:rbac:groups=compliance.kubecomply.io,resources=compliancescans,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=compliance.kubecomply.io,resources=compliancescans/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=compliance.kubecomply.io,resources=compliancescans/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods;namespaces;services;nodes;secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments;daemonsets;statefulsets,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles;clusterrolebindings;roles;rolebindings,verbs=get;list;watch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch

// Reconcile handles ComplianceScan create/update/delete events.
func (r *ComplianceScanReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Logger.With("compliancescan", req.NamespacedName)
	logger.Info("reconciling ComplianceScan")

	// Fetch the ComplianceScan resource.
	var scan v1alpha1.ComplianceScan
	if err := r.Get(ctx, req.NamespacedName, &scan); err != nil {
		if client.IgnoreNotFound(err) == nil {
			logger.Info("ComplianceScan not found, likely deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetching ComplianceScan: %w", err)
	}

	// Handle deletion with finalizer.
	if !scan.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&scan, finalizerName) {
			logger.Info("cleaning up ComplianceScan resources")
			controllerutil.RemoveFinalizer(&scan, finalizerName)
			if err := r.Update(ctx, &scan); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if not present.
	if !controllerutil.ContainsFinalizer(&scan, finalizerName) {
		controllerutil.AddFinalizer(&scan, finalizerName)
		if err := r.Update(ctx, &scan); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	// Skip if already completed or running.
	if scan.Status.Phase == "Completed" || scan.Status.Phase == "Running" {
		logger.Info("scan already in terminal/active phase", "phase", scan.Status.Phase)
		return r.scheduleNext(scan)
	}

	// Set phase to Running.
	scan.Status.Phase = "Running"
	if err := r.Status().Update(ctx, &scan); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status to Running: %w", err)
	}

	// Execute the scan.
	result, err := r.executeScan(ctx, &scan, logger)
	if err != nil {
		logger.Error("scan execution failed", "error", err)
		return r.handleFailure(ctx, &scan, err)
	}

	// Update status with results.
	if err := r.updateStatusFromResult(ctx, &scan, result); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating status with results: %w", err)
	}

	// Record metrics.
	metrics.RecordScanResult(result, result.ClusterName, "success")

	// Upload to SaaS if enabled.
	r.uploadToSaaS(ctx, &scan, result, logger)

	logger.Info("scan completed successfully",
		"score", result.Summary.Score,
		"findings", result.Summary.TotalChecks,
	)

	return r.scheduleNext(scan)
}

// executeScan creates a scanner and runs it.
func (r *ComplianceScanReconciler) executeScan(ctx context.Context, scan *v1alpha1.ComplianceScan, logger *slog.Logger) (*scanner.ScanResult, error) {
	config := &scanner.ScanConfig{
		ScanType:    scan.Spec.ScanType,
		Namespaces:  scan.Spec.Namespaces,
		PolicyPaths: scan.Spec.PolicyPaths,
	}

	if scan.Spec.SeverityThreshold != "" {
		threshold, err := scanner.ParseSeverity(scan.Spec.SeverityThreshold)
		if err != nil {
			return nil, fmt.Errorf("invalid severity threshold: %w", err)
		}
		config.SeverityThreshold = threshold
	}

	if config.ScanType == "" {
		config.ScanType = "full"
	}

	// Build the scanner with analyzers.
	s := scanner.New(r.K8sClient, logger)
	s.SetPolicyEvaluator(r.PolicyEngine)
	s.RegisterAnalyzer(rbac.NewAnalyzer(r.K8sClient, logger))
	s.RegisterAnalyzer(network.NewAnalyzer(r.K8sClient, logger))
	s.RegisterAnalyzer(pss.NewChecker(r.K8sClient, logger))

	return s.Run(ctx, config)
}

// updateStatusFromResult writes scan results back to the CRD status.
func (r *ComplianceScanReconciler) updateStatusFromResult(ctx context.Context, scan *v1alpha1.ComplianceScan, result *scanner.ScanResult) error {
	now := metav1.Now()

	scan.Status.Phase = "Completed"
	scan.Status.ComplianceScore = result.Summary.Score
	scan.Status.TotalChecks = result.Summary.TotalChecks
	scan.Status.PassedChecks = result.Summary.PassedChecks
	scan.Status.FailedChecks = result.Summary.FailedChecks
	scan.Status.LastScanTime = &now
	scan.Status.Findings = v1alpha1.FindingSummary{
		Critical: result.Summary.FindingsBySeverity[scanner.SeverityCritical],
		High:     result.Summary.FindingsBySeverity[scanner.SeverityHigh],
		Medium:   result.Summary.FindingsBySeverity[scanner.SeverityMedium],
		Low:      result.Summary.FindingsBySeverity[scanner.SeverityLow],
		Info:     result.Summary.FindingsBySeverity[scanner.SeverityInfo],
	}

	// Set condition.
	condition := metav1.Condition{
		Type:               "ScanComplete",
		Status:             metav1.ConditionTrue,
		LastTransitionTime: now,
		Reason:             "ScanSucceeded",
		Message:            fmt.Sprintf("Scan completed with score %.1f%% (%d/%d checks passed)", result.Summary.Score, result.Summary.PassedChecks, result.Summary.TotalChecks),
	}
	setCondition(&scan.Status.Conditions, condition)

	return r.Status().Update(ctx, scan)
}

// handleFailure sets the scan phase to Failed and records the error.
func (r *ComplianceScanReconciler) handleFailure(ctx context.Context, scan *v1alpha1.ComplianceScan, scanErr error) (ctrl.Result, error) {
	now := metav1.Now()
	scan.Status.Phase = "Failed"

	condition := metav1.Condition{
		Type:               "ScanComplete",
		Status:             metav1.ConditionFalse,
		LastTransitionTime: now,
		Reason:             "ScanFailed",
		Message:            scanErr.Error(),
	}
	setCondition(&scan.Status.Conditions, condition)

	if err := r.Status().Update(ctx, scan); err != nil {
		return ctrl.Result{}, fmt.Errorf("updating failed status: %w", err)
	}

	// Record failure metric.
	metrics.ScanTotal.WithLabelValues(scan.Spec.ScanType, "failure").Inc()

	// Requeue after a delay for retry.
	return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
}

// uploadToSaaS sends results to the SaaS platform if configured.
func (r *ComplianceScanReconciler) uploadToSaaS(ctx context.Context, scan *v1alpha1.ComplianceScan, result *scanner.ScanResult, logger *slog.Logger) {
	if r.SaaSClient == nil {
		return
	}
	if scan.Spec.SaaSIntegration == nil || !scan.Spec.SaaSIntegration.Enabled {
		return
	}

	// Validate license if not already authenticated.
	if !r.SaaSClient.IsAuthenticated() && scan.Spec.SaaSIntegration.LicenseKeySecretRef != nil {
		secretRef := scan.Spec.SaaSIntegration.LicenseKeySecretRef
		secret, err := r.K8sClient.GetSecret(ctx, scan.Namespace, secretRef.Name)
		if err != nil {
			logger.Warn("failed to read license key secret", "error", err)
			return
		}

		licenseKey := string(secret.Data[secretRef.Key])
		if licenseKey == "" {
			logger.Warn("license key is empty in secret", "secret", secretRef.Name, "key", secretRef.Key)
			return
		}

		if _, err := r.SaaSClient.ValidateLicense(ctx, licenseKey); err != nil {
			logger.Warn("license validation failed", "error", err)
			return
		}
	}

	// Upload results.
	if _, err := r.SaaSClient.UploadScanResults(ctx, "", result); err != nil {
		logger.Warn("failed to upload scan results to SaaS", "error", err)
	}
}

// scheduleNext calculates when the next scan should run based on the schedule.
func (r *ComplianceScanReconciler) scheduleNext(scan v1alpha1.ComplianceScan) (ctrl.Result, error) {
	if scan.Spec.Schedule == "" {
		return ctrl.Result{}, nil
	}

	// For scheduled scans, requeue after a fixed interval.
	// A production implementation would parse the cron expression properly.
	return ctrl.Result{RequeueAfter: 1 * time.Hour}, nil
}

// setCondition updates or appends a condition in the conditions slice.
func setCondition(conditions *[]metav1.Condition, condition metav1.Condition) {
	for i, c := range *conditions {
		if c.Type == condition.Type {
			(*conditions)[i] = condition
			return
		}
	}
	*conditions = append(*conditions, condition)
}

// SetupWithManager registers the reconciler with the controller manager.
func (r *ComplianceScanReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.ComplianceScan{}).
		Complete(r)
}
