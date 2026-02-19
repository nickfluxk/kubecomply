# METADATA
# title: CIS Kubernetes Benchmark - Section 2 etcd
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 2 checks for
#   etcd server configuration security.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "2"
package cis.etcd

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-2.1: Ensure client-cert-auth is set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-2.1",
	"Ensure etcd client-cert-auth is set to true",
	"etcd client certificate authentication is not enabled",
	"critical",
	concat("\n", [
		"Enable client certificate authentication for etcd:",
		"",
		"# In the etcd manifest or configuration:",
		"spec:",
		"  containers:",
		"  - command:",
		"    - etcd",
		"    - --client-cert-auth=true",
		"    - --cert-file=/etc/kubernetes/pki/etcd/server.crt",
		"    - --key-file=/etc/kubernetes/pki/etcd/server.key",
		"    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
	]),
	_etcd_resource,
	{
		"parameter": "client-cert-auth",
		"current_value": _get_arg_value_or_default("client-cert-auth", "not set"),
		"expected_value": "true",
	},
) if {
	not _client_cert_auth_enabled
}

results contains helpers.result_pass(
	"KC-CIS-2.1",
	"Ensure etcd client-cert-auth is set to true",
	"etcd client certificate authentication is enabled",
	_etcd_resource,
) if {
	_client_cert_auth_enabled
}

_client_cert_auth_enabled if {
	_get_arg_value("client-cert-auth") == "true"
}

# ============================================================
# KC-CIS-2.2: Ensure auto-tls is not set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-2.2",
	"Ensure etcd auto-tls is not set to true",
	"etcd auto-tls is enabled (uses self-signed certificates which are insecure)",
	"critical",
	concat("\n", [
		"Disable auto-tls and use proper certificates:",
		"",
		"# Remove --auto-tls=true from etcd arguments.",
		"# Use proper TLS certificates instead:",
		"spec:",
		"  containers:",
		"  - command:",
		"    - etcd",
		"    - --cert-file=/etc/kubernetes/pki/etcd/server.crt",
		"    - --key-file=/etc/kubernetes/pki/etcd/server.key",
		"    - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
		"    # Do NOT use: --auto-tls=true",
	]),
	_etcd_resource,
	{
		"parameter": "auto-tls",
		"current_value": "true",
		"expected_value": "false or not set",
	},
) if {
	_get_arg_value("auto-tls") == "true"
}

results contains helpers.result_pass(
	"KC-CIS-2.2",
	"Ensure etcd auto-tls is not set to true",
	"etcd auto-tls is not enabled",
	_etcd_resource,
) if {
	not _auto_tls_enabled
}

_auto_tls_enabled if {
	_get_arg_value("auto-tls") == "true"
}

# ============================================================
# KC-CIS-2.3: Ensure peer-client-cert-auth is set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-2.3",
	"Ensure etcd peer-client-cert-auth is set to true",
	"etcd peer client certificate authentication is not enabled",
	"critical",
	concat("\n", [
		"Enable peer client certificate authentication:",
		"",
		"spec:",
		"  containers:",
		"  - command:",
		"    - etcd",
		"    - --peer-client-cert-auth=true",
		"    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
		"    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
		"    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
	]),
	_etcd_resource,
	{
		"parameter": "peer-client-cert-auth",
		"current_value": _get_arg_value_or_default("peer-client-cert-auth", "not set"),
		"expected_value": "true",
	},
) if {
	not _peer_client_cert_auth_enabled
}

results contains helpers.result_pass(
	"KC-CIS-2.3",
	"Ensure etcd peer-client-cert-auth is set to true",
	"etcd peer client certificate authentication is enabled",
	_etcd_resource,
) if {
	_peer_client_cert_auth_enabled
}

_peer_client_cert_auth_enabled if {
	_get_arg_value("peer-client-cert-auth") == "true"
}

# ============================================================
# KC-CIS-2.4: Ensure peer-auto-tls is not set to true
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-2.4",
	"Ensure etcd peer-auto-tls is not set to true",
	"etcd peer-auto-tls is enabled (uses self-signed peer certificates)",
	"critical",
	concat("\n", [
		"Disable peer-auto-tls and use proper peer certificates:",
		"",
		"# Remove --peer-auto-tls=true from etcd arguments.",
		"# Use proper peer TLS certificates instead:",
		"spec:",
		"  containers:",
		"  - command:",
		"    - etcd",
		"    - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
		"    - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
		"    - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
		"    # Do NOT use: --peer-auto-tls=true",
	]),
	_etcd_resource,
	{
		"parameter": "peer-auto-tls",
		"current_value": "true",
		"expected_value": "false or not set",
	},
) if {
	_get_arg_value("peer-auto-tls") == "true"
}

results contains helpers.result_pass(
	"KC-CIS-2.4",
	"Ensure etcd peer-auto-tls is not set to true",
	"etcd peer-auto-tls is not enabled",
	_etcd_resource,
) if {
	not _peer_auto_tls_enabled
}

_peer_auto_tls_enabled if {
	_get_arg_value("peer-auto-tls") == "true"
}

# ============================================================
# Internal helpers
# ============================================================

_etcd_resource := {
	"kind": "Pod",
	"metadata": {"name": "etcd", "namespace": "kube-system"},
}

_has_arg(name) if {
	input.etcd_config.arguments[name]
}

_has_arg(name) if {
	arg := input.etcd_config.args[_]
	startswith(arg, concat("", ["--", name]))
}

_get_arg_value(name) := value if {
	value := input.etcd_config.arguments[name]
}

_get_arg_value(name) := value if {
	arg := input.etcd_config.args[_]
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
