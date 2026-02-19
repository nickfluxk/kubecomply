# METADATA
# title: CIS Kubernetes Benchmark - Section 1.4 Scheduler
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 1.4 checks for
#   Scheduler configuration security.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "1.4"
package cis.control_plane.scheduler

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-1.4.1: Ensure profiling is disabled
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.4.1",
	"Ensure profiling is disabled for Scheduler",
	"Scheduler profiling is enabled or not explicitly disabled",
	"medium",
	concat("\n", [
		"Disable profiling on the scheduler:",
		"",
		"# In /etc/kubernetes/manifests/kube-scheduler.yaml:",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-scheduler",
		"    - --profiling=false",
	]),
	_scheduler_resource,
	{
		"parameter": "profiling",
		"current_value": _get_arg_value_or_default("profiling", "true (default)"),
		"expected_value": "false",
	},
) if {
	not _profiling_disabled
}

results contains helpers.result_pass(
	"KC-CIS-1.4.1",
	"Ensure profiling is disabled for Scheduler",
	"Scheduler profiling is disabled",
	_scheduler_resource,
) if {
	_profiling_disabled
}

_profiling_disabled if {
	_get_arg_value("profiling") == "false"
}

# ============================================================
# KC-CIS-1.4.2: Ensure bind-address is set to 127.0.0.1
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.4.2",
	"Ensure bind-address is set to 127.0.0.1",
	sprintf("Scheduler bind-address is set to '%s' (should be 127.0.0.1)", [_get_arg_value("bind-address")]),
	"high",
	concat("\n", [
		"Set --bind-address=127.0.0.1 on the scheduler:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-scheduler",
		"    - --bind-address=127.0.0.1",
	]),
	_scheduler_resource,
	{
		"parameter": "bind-address",
		"current_value": _get_arg_value("bind-address"),
		"expected_value": "127.0.0.1",
	},
) if {
	_has_arg("bind-address")
	_get_arg_value("bind-address") != "127.0.0.1"
}

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.4.2",
	"Ensure bind-address is set to 127.0.0.1",
	"Scheduler bind-address is not explicitly set",
	"high",
	concat("\n", [
		"Explicitly set --bind-address=127.0.0.1 on the scheduler:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-scheduler",
		"    - --bind-address=127.0.0.1",
	]),
	_scheduler_resource,
	{
		"parameter": "bind-address",
		"current_value": "not set",
		"expected_value": "127.0.0.1",
	},
) if {
	not _has_arg("bind-address")
}

results contains helpers.result_pass(
	"KC-CIS-1.4.2",
	"Ensure bind-address is set to 127.0.0.1",
	"Scheduler bind-address is correctly set to 127.0.0.1",
	_scheduler_resource,
) if {
	_get_arg_value("bind-address") == "127.0.0.1"
}

# ============================================================
# Internal helpers
# ============================================================

_scheduler_resource := {
	"kind": "Pod",
	"metadata": {"name": "kube-scheduler", "namespace": "kube-system"},
}

_has_arg(name) if {
	input.scheduler_config.arguments[name]
}

_has_arg(name) if {
	arg := input.scheduler_config.args[_]
	startswith(arg, concat("", ["--", name]))
}

_get_arg_value(name) := value if {
	value := input.scheduler_config.arguments[name]
}

_get_arg_value(name) := value if {
	arg := input.scheduler_config.args[_]
	prefix := concat("", ["--", name, "="])
	startswith(arg, prefix)
	value := substring(arg, count(prefix), -1)
}

_get_arg_value_or_default(name, _default_val) := value if {
	value := _get_arg_value(name)
}

_get_arg_value_or_default(name, default_val) := default_val if {
	not _has_arg(name)
}
