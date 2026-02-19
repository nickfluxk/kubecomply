# METADATA
# title: CIS Kubernetes Benchmark - Section 1.2 API Server
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 1.2 checks for
#   API Server configuration security.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "1.2"
package cis.control_plane.api_server

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-1.2.1: Ensure anonymous-auth is set to false
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.1",
	"Ensure anonymous-auth is set to false",
	"API Server has anonymous authentication enabled",
	"critical",
	concat("\n", [
		"Set --anonymous-auth=false on the API server:",
		"",
		"# In the kube-apiserver manifest (/etc/kubernetes/manifests/kube-apiserver.yaml):",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --anonymous-auth=false",
	]),
	_api_server_resource,
	{
		"parameter": "anonymous-auth",
		"current_value": "true",
		"expected_value": "false",
	},
) if {
	_get_arg_value("anonymous-auth") == "true"
}

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.1",
	"Ensure anonymous-auth is set to false",
	"API Server anonymous-auth setting not found (defaults to true)",
	"critical",
	concat("\n", [
		"Explicitly set --anonymous-auth=false on the API server:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --anonymous-auth=false",
	]),
	_api_server_resource,
	{
		"parameter": "anonymous-auth",
		"current_value": "not set (defaults to true)",
		"expected_value": "false",
	},
) if {
	not _has_arg("anonymous-auth")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.1",
	"Ensure anonymous-auth is set to false",
	"API Server has anonymous authentication disabled",
	_api_server_resource,
) if {
	_get_arg_value("anonymous-auth") == "false"
}

# ============================================================
# KC-CIS-1.2.2: Ensure basic-auth-file is not set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.2",
	"Ensure basic-auth-file is not set",
	"API Server uses basic authentication file (deprecated and insecure)",
	"critical",
	concat("\n", [
		"Remove --basic-auth-file from the API server arguments:",
		"",
		"# In kube-apiserver manifest, remove the line:",
		"# - --basic-auth-file=/path/to/file",
		"",
		"# Use certificate-based or OIDC authentication instead.",
	]),
	_api_server_resource,
	{
		"parameter": "basic-auth-file",
		"current_value": _get_arg_value("basic-auth-file"),
		"expected_value": "not set",
	},
) if {
	_has_arg("basic-auth-file")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.2",
	"Ensure basic-auth-file is not set",
	"API Server does not use basic authentication file",
	_api_server_resource,
) if {
	not _has_arg("basic-auth-file")
}

# ============================================================
# KC-CIS-1.2.3: Ensure token-auth-file is not set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.3",
	"Ensure token-auth-file is not set",
	"API Server uses static token authentication file (insecure)",
	"critical",
	concat("\n", [
		"Remove --token-auth-file from the API server arguments:",
		"",
		"# In kube-apiserver manifest, remove the line:",
		"# - --token-auth-file=/path/to/file",
		"",
		"# Use ServiceAccount tokens, OIDC, or webhook authentication instead.",
	]),
	_api_server_resource,
	{
		"parameter": "token-auth-file",
		"current_value": _get_arg_value("token-auth-file"),
		"expected_value": "not set",
	},
) if {
	_has_arg("token-auth-file")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.3",
	"Ensure token-auth-file is not set",
	"API Server does not use static token authentication file",
	_api_server_resource,
) if {
	not _has_arg("token-auth-file")
}

# ============================================================
# KC-CIS-1.2.4: Ensure kubelet-https is enabled
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.4",
	"Ensure kubelet-https is enabled",
	"API Server has kubelet-https disabled",
	"critical",
	concat("\n", [
		"Ensure --kubelet-https is not set to false:",
		"",
		"# Remove --kubelet-https=false from kube-apiserver arguments.",
		"# The default is true, so simply removing the flag is sufficient.",
	]),
	_api_server_resource,
	{
		"parameter": "kubelet-https",
		"current_value": "false",
		"expected_value": "true (default)",
	},
) if {
	_get_arg_value("kubelet-https") == "false"
}

results contains helpers.result_pass(
	"KC-CIS-1.2.4",
	"Ensure kubelet-https is enabled",
	"API Server kubelet HTTPS communication is enabled",
	_api_server_resource,
) if {
	not _get_arg_value("kubelet-https") == "false"
}

# ============================================================
# KC-CIS-1.2.5: Ensure audit-log-path is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.5",
	"Ensure audit-log-path is set",
	"API Server audit logging is not configured",
	"high",
	concat("\n", [
		"Enable audit logging on the API server:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --audit-log-path=/var/log/kubernetes/audit.log",
		"    - --audit-policy-file=/etc/kubernetes/audit-policy.yaml",
		"    volumeMounts:",
		"    - mountPath: /var/log/kubernetes",
		"      name: audit-log",
		"    - mountPath: /etc/kubernetes/audit-policy.yaml",
		"      name: audit-policy",
		"      readOnly: true",
		"  volumes:",
		"  - hostPath:",
		"      path: /var/log/kubernetes",
		"      type: DirectoryOrCreate",
		"    name: audit-log",
	]),
	_api_server_resource,
	{
		"parameter": "audit-log-path",
		"current_value": "not set",
		"expected_value": "a valid file path",
	},
) if {
	not _has_arg("audit-log-path")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.5",
	"Ensure audit-log-path is set",
	sprintf("API Server audit log path is set to '%s'", [_get_arg_value("audit-log-path")]),
	_api_server_resource,
) if {
	_has_arg("audit-log-path")
}

# ============================================================
# KC-CIS-1.2.6: Ensure audit-log-maxage is set to 30 or more
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.6",
	"Ensure audit-log-maxage is set to 30 or more",
	sprintf("API Server audit-log-maxage is set to %s (should be >= 30)", [_get_arg_value("audit-log-maxage")]),
	"medium",
	concat("\n", [
		"Set --audit-log-maxage to at least 30 days:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --audit-log-maxage=30",
	]),
	_api_server_resource,
	{
		"parameter": "audit-log-maxage",
		"current_value": _get_arg_value("audit-log-maxage"),
		"expected_value": ">= 30",
	},
) if {
	_has_arg("audit-log-maxage")
	to_number(_get_arg_value("audit-log-maxage")) < 30
}

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.6",
	"Ensure audit-log-maxage is set to 30 or more",
	"API Server audit-log-maxage is not set",
	"medium",
	concat("\n", [
		"Set --audit-log-maxage to at least 30 days:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --audit-log-maxage=30",
	]),
	_api_server_resource,
	{
		"parameter": "audit-log-maxage",
		"current_value": "not set",
		"expected_value": ">= 30",
	},
) if {
	not _has_arg("audit-log-maxage")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.6",
	"Ensure audit-log-maxage is set to 30 or more",
	sprintf("API Server audit-log-maxage is set to %s", [_get_arg_value("audit-log-maxage")]),
	_api_server_resource,
) if {
	_has_arg("audit-log-maxage")
	to_number(_get_arg_value("audit-log-maxage")) >= 30
}

# ============================================================
# KC-CIS-1.2.7: Ensure always-admit admission controller is not enabled
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.7",
	"Ensure AlwaysAdmit admission controller is not enabled",
	"API Server has AlwaysAdmit admission controller enabled",
	"critical",
	concat("\n", [
		"Remove AlwaysAdmit from --enable-admission-plugins:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --enable-admission-plugins=NodeRestriction,PodSecurity",
		"    # Do NOT include AlwaysAdmit in the list",
	]),
	_api_server_resource,
	{
		"parameter": "enable-admission-plugins",
		"issue": "AlwaysAdmit is enabled",
	},
) if {
	plugins := _get_arg_value("enable-admission-plugins")
	contains(plugins, "AlwaysAdmit")
}

results contains helpers.result_pass(
	"KC-CIS-1.2.7",
	"Ensure AlwaysAdmit admission controller is not enabled",
	"API Server does not have AlwaysAdmit admission controller enabled",
	_api_server_resource,
) if {
	not _always_admit_enabled
}

_always_admit_enabled if {
	plugins := _get_arg_value("enable-admission-plugins")
	contains(plugins, "AlwaysAdmit")
}

# ============================================================
# KC-CIS-1.2.8: Ensure AlwaysPullImages admission controller is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.8",
	"Ensure AlwaysPullImages admission controller is set",
	"API Server does not have AlwaysPullImages admission controller enabled",
	"medium",
	concat("\n", [
		"Enable AlwaysPullImages admission controller:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --enable-admission-plugins=NodeRestriction,AlwaysPullImages,PodSecurity",
	]),
	_api_server_resource,
	{
		"parameter": "enable-admission-plugins",
		"issue": "AlwaysPullImages not enabled",
	},
) if {
	not _always_pull_images_enabled
}

results contains helpers.result_pass(
	"KC-CIS-1.2.8",
	"Ensure AlwaysPullImages admission controller is set",
	"API Server has AlwaysPullImages admission controller enabled",
	_api_server_resource,
) if {
	_always_pull_images_enabled
}

_always_pull_images_enabled if {
	plugins := _get_arg_value("enable-admission-plugins")
	contains(plugins, "AlwaysPullImages")
}

# ============================================================
# KC-CIS-1.2.9: Ensure NodeRestriction admission plugin is set
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-1.2.9",
	"Ensure NodeRestriction admission plugin is set",
	"API Server does not have NodeRestriction admission plugin enabled",
	"high",
	concat("\n", [
		"Enable NodeRestriction admission controller:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - kube-apiserver",
		"    - --enable-admission-plugins=NodeRestriction,PodSecurity",
	]),
	_api_server_resource,
	{
		"parameter": "enable-admission-plugins",
		"issue": "NodeRestriction not enabled",
	},
) if {
	not _node_restriction_enabled
}

results contains helpers.result_pass(
	"KC-CIS-1.2.9",
	"Ensure NodeRestriction admission plugin is set",
	"API Server has NodeRestriction admission plugin enabled",
	_api_server_resource,
) if {
	_node_restriction_enabled
}

_node_restriction_enabled if {
	plugins := _get_arg_value("enable-admission-plugins")
	contains(plugins, "NodeRestriction")
}

# ============================================================
# Internal helpers
# ============================================================

_api_server_resource := {"kind": "Pod", "metadata": {"name": "kube-apiserver", "namespace": "kube-system"}}

# Parse arguments from api_server_config.
# Supports both --arg=value format in an arguments list and
# a flat key-value map in api_server_config.
_has_arg(name) if {
	input.api_server_config.arguments[name]
}

_has_arg(name) if {
	arg := input.api_server_config.args[_]
	startswith(arg, concat("", ["--", name]))
}

_get_arg_value(name) := value if {
	value := input.api_server_config.arguments[name]
}

_get_arg_value(name) := value if {
	arg := input.api_server_config.args[_]
	prefix := concat("", ["--", name, "="])
	startswith(arg, prefix)
	value := substring(arg, count(prefix), -1)
}
