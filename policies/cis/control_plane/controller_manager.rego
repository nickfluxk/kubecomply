# METADATA
# title: CIS Kubernetes Benchmark - Section 1.3 Controller Manager
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 1.3 checks for
#   Controller Manager configuration security.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "1.3"
package cis.control_plane.controller_manager

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-1.3.1: Ensure terminated-pod-gc-threshold is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.3.1",
	"Ensure terminated-pod-gc-threshold is set",
	"Controller Manager terminated-pod-gc-threshold is not set",
	"medium",
	concat("\n", [
		"Set --terminated-pod-gc-threshold on the controller manager:",
		"",
		"# In /etc/kubernetes/manifests/kube-controller-manager.yaml:",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-controller-manager",
		"    - --terminated-pod-gc-threshold=12500",
	]),
	_controller_manager_resource,
	{
		"parameter": "terminated-pod-gc-threshold",
		"current_value": "not set",
		"expected_value": "a positive integer (e.g., 12500)",
	},
) if {
	not _has_arg("terminated-pod-gc-threshold")
}

results contains helpers.result_pass(
	"KC-CIS-1.3.1",
	"Ensure terminated-pod-gc-threshold is set",
	sprintf("Controller Manager terminated-pod-gc-threshold is set to '%s'", [_get_arg_value("terminated-pod-gc-threshold")]),
	_controller_manager_resource,
) if {
	_has_arg("terminated-pod-gc-threshold")
}

# ============================================================
# KC-CIS-1.3.2: Ensure profiling is disabled
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.3.2",
	"Ensure profiling is disabled for Controller Manager",
	"Controller Manager profiling is enabled",
	"medium",
	concat("\n", [
		"Disable profiling on the controller manager:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-controller-manager",
		"    - --profiling=false",
	]),
	_controller_manager_resource,
	{
		"parameter": "profiling",
		"current_value": _get_arg_value_or_default("profiling", "true (default)"),
		"expected_value": "false",
	},
) if {
	not _profiling_disabled
}

results contains helpers.result_pass(
	"KC-CIS-1.3.2",
	"Ensure profiling is disabled for Controller Manager",
	"Controller Manager profiling is disabled",
	_controller_manager_resource,
) if {
	_profiling_disabled
}

_profiling_disabled if {
	_get_arg_value("profiling") == "false"
}

# ============================================================
# KC-CIS-1.3.3: Ensure use-service-account-credentials is set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.3.3",
	"Ensure use-service-account-credentials is set to true",
	"Controller Manager is not using individual service account credentials",
	"high",
	concat("\n", [
		"Enable use-service-account-credentials:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-controller-manager",
		"    - --use-service-account-credentials=true",
	]),
	_controller_manager_resource,
	{
		"parameter": "use-service-account-credentials",
		"current_value": _get_arg_value_or_default("use-service-account-credentials", "false (default)"),
		"expected_value": "true",
	},
) if {
	not _use_sa_credentials
}

results contains helpers.result_pass(
	"KC-CIS-1.3.3",
	"Ensure use-service-account-credentials is set to true",
	"Controller Manager uses individual service account credentials",
	_controller_manager_resource,
) if {
	_use_sa_credentials
}

_use_sa_credentials if {
	_get_arg_value("use-service-account-credentials") == "true"
}

# ============================================================
# KC-CIS-1.3.4: Ensure service-account-private-key-file is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.3.4",
	"Ensure service-account-private-key-file is set",
	"Controller Manager service-account-private-key-file is not configured",
	"high",
	concat("\n", [
		"Set --service-account-private-key-file on the controller manager:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-controller-manager",
		"    - --service-account-private-key-file=/etc/kubernetes/pki/sa.key",
	]),
	_controller_manager_resource,
	{
		"parameter": "service-account-private-key-file",
		"current_value": "not set",
		"expected_value": "path to private key file",
	},
) if {
	not _has_arg("service-account-private-key-file")
}

results contains helpers.result_pass(
	"KC-CIS-1.3.4",
	"Ensure service-account-private-key-file is set",
	sprintf("Controller Manager service-account-private-key-file is set to '%s'", [_get_arg_value("service-account-private-key-file")]),
	_controller_manager_resource,
) if {
	_has_arg("service-account-private-key-file")
}

# ============================================================
# KC-CIS-1.3.5: Ensure root-ca-file is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.3.5",
	"Ensure root-ca-file is set",
	"Controller Manager root-ca-file is not configured",
	"high",
	concat("\n", [
		"Set --root-ca-file on the controller manager:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-controller-manager",
		"    - --root-ca-file=/etc/kubernetes/pki/ca.crt",
	]),
	_controller_manager_resource,
	{
		"parameter": "root-ca-file",
		"current_value": "not set",
		"expected_value": "path to root CA certificate",
	},
) if {
	not _has_arg("root-ca-file")
}

results contains helpers.result_pass(
	"KC-CIS-1.3.5",
	"Ensure root-ca-file is set",
	sprintf("Controller Manager root-ca-file is set to '%s'", [_get_arg_value("root-ca-file")]),
	_controller_manager_resource,
) if {
	_has_arg("root-ca-file")
}

# ============================================================
# Internal helpers
# ============================================================

_controller_manager_resource := {
	"kind": "Pod",
	"metadata": {"name": "kube-controller-manager", "namespace": "kube-system"},
}

_has_arg(name) if {
	input.controller_manager_config.arguments[name]
}

_has_arg(name) if {
	arg := input.controller_manager_config.args[_]
	startswith(arg, concat("", ["--", name]))
}

_get_arg_value(name) := value if {
	value := input.controller_manager_config.arguments[name]
}

_get_arg_value(name) := value if {
	arg := input.controller_manager_config.args[_]
	prefix := concat("", ["--", name, "="])
	startswith(arg, prefix)
	value := substring(arg, count(prefix), -1)
}

_get_arg_value_or_default(name, _) := value if {
	value := _get_arg_value(name)
}

_get_arg_value_or_default(name, default_val) := default_val if {
	not _has_arg(name)
}
