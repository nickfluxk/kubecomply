# METADATA
# title: CIS Kubernetes Benchmark - Section 4.2 Kubelet
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 4.2 checks for
#   Kubelet configuration security.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "4.2"
package cis.worker_nodes.kubelet

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-4.2.1: Ensure anonymous-auth is set to false
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.1",
	"Ensure Kubelet anonymous-auth is set to false",
	"Kubelet anonymous authentication is enabled",
	"critical",
	concat("\n", [
		"Disable anonymous authentication on the Kubelet:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"authentication:",
		"  anonymous:",
		"    enabled: false",
		"",
		"# Or via CLI flag:",
		"# --anonymous-auth=false",
	]),
	_kubelet_resource,
	{
		"parameter": "anonymous-auth",
		"current_value": _get_config_value_str("authentication.anonymous.enabled", "anonymous-auth"),
		"expected_value": "false",
	},
) if {
	not _anonymous_auth_disabled
}

results contains helpers.result_pass(
	"KC-CIS-4.2.1",
	"Ensure Kubelet anonymous-auth is set to false",
	"Kubelet anonymous authentication is disabled",
	_kubelet_resource,
) if {
	_anonymous_auth_disabled
}

_anonymous_auth_disabled if {
	input.kubelet_config.authentication.anonymous.enabled == false
}

_anonymous_auth_disabled if {
	_get_arg_value("anonymous-auth") == "false"
}

# ============================================================
# KC-CIS-4.2.2: Ensure authorization mode is not AlwaysAllow
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.2",
	"Ensure Kubelet authorization mode is not AlwaysAllow",
	"Kubelet authorization mode is set to AlwaysAllow",
	"critical",
	concat("\n", [
		"Set Kubelet authorization to Webhook mode:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"authorization:",
		"  mode: Webhook",
		"",
		"# Or via CLI flag:",
		"# --authorization-mode=Webhook",
	]),
	_kubelet_resource,
	{
		"parameter": "authorization-mode",
		"current_value": "AlwaysAllow",
		"expected_value": "Webhook",
	},
) if {
	_authorization_always_allow
}

results contains helpers.result_pass(
	"KC-CIS-4.2.2",
	"Ensure Kubelet authorization mode is not AlwaysAllow",
	"Kubelet authorization mode is not AlwaysAllow",
	_kubelet_resource,
) if {
	not _authorization_always_allow
}

_authorization_always_allow if {
	input.kubelet_config.authorization.mode == "AlwaysAllow"
}

_authorization_always_allow if {
	_get_arg_value("authorization-mode") == "AlwaysAllow"
}

# ============================================================
# KC-CIS-4.2.3: Ensure client certificate rotation (RotateKubeletClientCertificate)
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.3",
	"Ensure Kubelet client certificate rotation is enabled",
	"Kubelet client certificate rotation (RotateKubeletClientCertificate) is not enabled",
	"high",
	concat("\n", [
		"Enable client certificate rotation:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"rotateCertificates: true",
		"",
		"# Or via CLI flag:",
		"# --rotate-certificates=true",
		"",
		"# Note: RotateKubeletClientCertificate feature gate is",
		"# enabled by default since Kubernetes 1.19.",
	]),
	_kubelet_resource,
	{
		"parameter": "rotateCertificates / rotate-certificates",
		"current_value": "not enabled",
		"expected_value": "true",
	},
) if {
	not _rotate_certificates_enabled
}

results contains helpers.result_pass(
	"KC-CIS-4.2.3",
	"Ensure Kubelet client certificate rotation is enabled",
	"Kubelet client certificate rotation is enabled",
	_kubelet_resource,
) if {
	_rotate_certificates_enabled
}

_rotate_certificates_enabled if {
	input.kubelet_config.rotateCertificates == true
}

_rotate_certificates_enabled if {
	_get_arg_value("rotate-certificates") == "true"
}

# ============================================================
# KC-CIS-4.2.4: Ensure read-only-port is set to 0
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.4",
	"Ensure Kubelet read-only-port is set to 0",
	sprintf("Kubelet read-only port is set to %s (should be 0/disabled)", [
		_get_config_value_str("readOnlyPort", "read-only-port"),
	]),
	"high",
	concat("\n", [
		"Disable the Kubelet read-only port:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"readOnlyPort: 0",
		"",
		"# Or via CLI flag:",
		"# --read-only-port=0",
	]),
	_kubelet_resource,
	{
		"parameter": "readOnlyPort / read-only-port",
		"current_value": _get_config_value_str("readOnlyPort", "read-only-port"),
		"expected_value": "0",
	},
) if {
	not _read_only_port_disabled
}

results contains helpers.result_pass(
	"KC-CIS-4.2.4",
	"Ensure Kubelet read-only-port is set to 0",
	"Kubelet read-only port is disabled",
	_kubelet_resource,
) if {
	_read_only_port_disabled
}

_read_only_port_disabled if {
	input.kubelet_config.readOnlyPort == 0
}

_read_only_port_disabled if {
	_get_arg_value("read-only-port") == "0"
}

# ============================================================
# KC-CIS-4.2.5: Ensure streaming connection idle timeout is not disabled
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.5",
	"Ensure Kubelet streaming connection idle timeout is not disabled",
	"Kubelet streaming connection idle timeout is set to 0 (disabled)",
	"medium",
	concat("\n", [
		"Set a non-zero streaming connection idle timeout:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"streamingConnectionIdleTimeout: 5m0s  # Default is 4h",
		"",
		"# Or via CLI flag:",
		"# --streaming-connection-idle-timeout=5m",
	]),
	_kubelet_resource,
	{
		"parameter": "streamingConnectionIdleTimeout",
		"current_value": "0 (disabled)",
		"expected_value": "non-zero duration (e.g., 5m0s)",
	},
) if {
	_streaming_timeout_disabled
}

results contains helpers.result_pass(
	"KC-CIS-4.2.5",
	"Ensure Kubelet streaming connection idle timeout is not disabled",
	"Kubelet streaming connection idle timeout is configured",
	_kubelet_resource,
) if {
	not _streaming_timeout_disabled
}

_streaming_timeout_disabled if {
	input.kubelet_config.streamingConnectionIdleTimeout == "0"
}

_streaming_timeout_disabled if {
	input.kubelet_config.streamingConnectionIdleTimeout == "0s"
}

_streaming_timeout_disabled if {
	_get_arg_value("streaming-connection-idle-timeout") == "0"
}

# ============================================================
# KC-CIS-4.2.6: Ensure protect-kernel-defaults is set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-4.2.6",
	"Ensure Kubelet protect-kernel-defaults is set to true",
	"Kubelet protect-kernel-defaults is not enabled",
	"high",
	concat("\n", [
		"Enable protect-kernel-defaults on the Kubelet:",
		"",
		"# In kubelet config (/var/lib/kubelet/config.yaml):",
		"protectKernelDefaults: true",
		"",
		"# Or via CLI flag:",
		"# --protect-kernel-defaults=true",
		"",
		"# Note: Ensure kernel parameters are set correctly before enabling,",
		"# as the kubelet will refuse to start if kernel defaults don't match.",
	]),
	_kubelet_resource,
	{
		"parameter": "protectKernelDefaults / protect-kernel-defaults",
		"current_value": "not enabled",
		"expected_value": "true",
	},
) if {
	not _protect_kernel_defaults
}

results contains helpers.result_pass(
	"KC-CIS-4.2.6",
	"Ensure Kubelet protect-kernel-defaults is set to true",
	"Kubelet protect-kernel-defaults is enabled",
	_kubelet_resource,
) if {
	_protect_kernel_defaults
}

_protect_kernel_defaults if {
	input.kubelet_config.protectKernelDefaults == true
}

_protect_kernel_defaults if {
	_get_arg_value("protect-kernel-defaults") == "true"
}

# ============================================================
# Internal helpers
# ============================================================

_kubelet_resource := {
	"kind": "Node",
	"metadata": {"name": object.get(object.get(input, "kubelet_config", {}), "node_name", "worker-node")},
}

_has_arg(name) if {
	input.kubelet_config.arguments[name]
}

_has_arg(name) if {
	arg := input.kubelet_config.args[_]
	startswith(arg, concat("", ["--", name]))
}

_get_arg_value(name) := value if {
	value := input.kubelet_config.arguments[name]
}

_get_arg_value(name) := value if {
	arg := input.kubelet_config.args[_]
	prefix := concat("", ["--", name, "="])
	startswith(arg, prefix)
	value := substring(arg, count(prefix), -1)
}

# Helper to get config value as string for display.
# Tries the config file field first, then the CLI argument.
_get_config_value_str(config_field, arg_name) := sprintf("%v", [input.kubelet_config[config_field]]) if {
	helpers.has_key(input.kubelet_config, config_field)
}

_get_config_value_str(config_field, arg_name) := _get_arg_value(arg_name) if {
	not helpers.has_key(input.kubelet_config, config_field)
	_has_arg(arg_name)
}

_get_config_value_str(config_field, arg_name) := "not set" if {
	not helpers.has_key(input.kubelet_config, config_field)
	not _has_arg(arg_name)
}
