package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ComplianceScanSpec defines the desired state of a ComplianceScan.
type ComplianceScanSpec struct {
	// ScanType specifies which scan to run.
	// +kubebuilder:validation:Enum=cis;rbac;network;pss;full
	// +kubebuilder:default=full
	ScanType string `json:"scanType,omitempty"`

	// Schedule is a cron expression for recurring scans. If empty, scan runs once.
	Schedule string `json:"schedule,omitempty"`

	// Namespaces to scope the scan. Empty means all namespaces.
	Namespaces []string `json:"namespaces,omitempty"`

	// PolicyPaths specifies custom policy directories to include.
	PolicyPaths []string `json:"policyPaths,omitempty"`

	// SeverityThreshold filters findings at or above this level.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	// +kubebuilder:default=info
	SeverityThreshold string `json:"severityThreshold,omitempty"`

	// SaaSIntegration controls whether results are sent to KubeComply SaaS.
	SaaSIntegration *SaaSIntegrationSpec `json:"saasIntegration,omitempty"`
}

// SaaSIntegrationSpec configures the connection to KubeComply Professional SaaS.
type SaaSIntegrationSpec struct {
	// Enabled activates SaaS integration.
	Enabled bool `json:"enabled,omitempty"`

	// LicenseKeySecretRef references a Secret containing the license key.
	LicenseKeySecretRef *SecretKeyRef `json:"licenseKeySecretRef,omitempty"`

	// Endpoint is the SaaS API URL. Defaults to https://api.kubecomply.io.
	Endpoint string `json:"endpoint,omitempty"`
}

// SecretKeyRef references a key in a Secret.
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// ComplianceScanStatus defines the observed state of a ComplianceScan.
type ComplianceScanStatus struct {
	// Phase is the current scan phase.
	// +kubebuilder:validation:Enum=Pending;Running;Completed;Failed
	Phase string `json:"phase,omitempty"`

	// ComplianceScore is the overall compliance percentage (0-100).
	ComplianceScore float64 `json:"complianceScore,omitempty"`

	// TotalChecks is the number of checks evaluated.
	TotalChecks int `json:"totalChecks,omitempty"`

	// PassedChecks is the number of passing checks.
	PassedChecks int `json:"passedChecks,omitempty"`

	// FailedChecks is the number of failing checks.
	FailedChecks int `json:"failedChecks,omitempty"`

	// Findings is the summary of findings by severity.
	Findings FindingSummary `json:"findings,omitempty"`

	// LastScanTime is when the last scan completed.
	LastScanTime *metav1.Time `json:"lastScanTime,omitempty"`

	// NextScanTime is when the next scheduled scan will run.
	NextScanTime *metav1.Time `json:"nextScanTime,omitempty"`

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// FindingSummary contains counts of findings by severity.
type FindingSummary struct {
	Critical int `json:"critical,omitempty"`
	High     int `json:"high,omitempty"`
	Medium   int `json:"medium,omitempty"`
	Low      int `json:"low,omitempty"`
	Info     int `json:"info,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Score",type=number,JSONPath=`.status.complianceScore`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Passed",type=integer,JSONPath=`.status.passedChecks`
// +kubebuilder:printcolumn:name="Failed",type=integer,JSONPath=`.status.failedChecks`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ComplianceScan is the Schema for the compliancescans API.
type ComplianceScan struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ComplianceScanSpec   `json:"spec,omitempty"`
	Status ComplianceScanStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ComplianceScanList contains a list of ComplianceScan.
type ComplianceScanList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ComplianceScan `json:"items"`
}

// CompliancePolicySpec defines the desired state of a CompliancePolicy.
type CompliancePolicySpec struct {
	// Category of this policy (cis, nsa, rbac, pss, network, custom).
	// +kubebuilder:validation:Enum=cis;nsa;rbac;pss;network;custom
	Category string `json:"category"`

	// Severity is the default severity for findings from this policy.
	// +kubebuilder:validation:Enum=critical;high;medium;low;info
	Severity string `json:"severity"`

	// RegoPolicy is the inline Rego policy content.
	RegoPolicy string `json:"regoPolicy,omitempty"`

	// RegoPolicyConfigMapRef references a ConfigMap containing the Rego policy.
	RegoPolicyConfigMapRef *ConfigMapKeyRef `json:"regoPolicyConfigMapRef,omitempty"`

	// Enabled controls whether this policy is evaluated during scans.
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
}

// ConfigMapKeyRef references a key in a ConfigMap.
type ConfigMapKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// CompliancePolicyStatus defines the observed state of a CompliancePolicy.
type CompliancePolicyStatus struct {
	// Ready indicates if the policy has been successfully loaded.
	Ready bool `json:"ready,omitempty"`

	// Message provides details about the policy status.
	Message string `json:"message,omitempty"`

	// LastEvaluated is when this policy was last evaluated.
	LastEvaluated *metav1.Time `json:"lastEvaluated,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// CompliancePolicy is the Schema for the compliancepolicies API.
type CompliancePolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CompliancePolicySpec   `json:"spec,omitempty"`
	Status CompliancePolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// CompliancePolicyList contains a list of CompliancePolicy.
type CompliancePolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CompliancePolicy `json:"items"`
}
