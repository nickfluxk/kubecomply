# METADATA
# title: CIS Kubernetes Benchmark - Section 5.3 Network Policies
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 5.3 checks for
#   NetworkPolicy configuration per namespace.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "5.3"
package cis.policies.network

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-5.3.1: Ensure NetworkPolicy is configured for every namespace
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.3.1",
	"Ensure NetworkPolicy is configured for every namespace",
	sprintf("Namespace '%s' has no NetworkPolicy configured", [ns.metadata.name]),
	"high",
	concat("\n", [
		sprintf("Create a NetworkPolicy for namespace '%s':", [ns.metadata.name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		sprintf("  name: default-deny-all", []),
		sprintf("  namespace: %s", [ns.metadata.name]),
		"spec:",
		"  podSelector: {}",
		"  policyTypes:",
		"  - Ingress",
		"  - Egress",
	]),
	ns,
	{
		"namespace": ns.metadata.name,
		"network_policies_count": "0",
	},
) if {
	ns := input.namespaces[_]
	not _is_system_namespace(ns.metadata.name)
	not _namespace_has_netpol(ns.metadata.name)
}

results contains helpers.result_pass(
	"KC-CIS-5.3.1",
	"Ensure NetworkPolicy is configured for every namespace",
	sprintf("Namespace '%s' has NetworkPolicy configured", [ns.metadata.name]),
	ns,
) if {
	ns := input.namespaces[_]
	not _is_system_namespace(ns.metadata.name)
	_namespace_has_netpol(ns.metadata.name)
}

# ============================================================
# KC-CIS-5.3.2: Ensure default deny NetworkPolicy exists per namespace
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.3.2",
	"Ensure default deny NetworkPolicy exists per namespace",
	sprintf("Namespace '%s' lacks a default-deny NetworkPolicy", [ns.metadata.name]),
	"high",
	concat("\n", [
		sprintf("Create a default-deny NetworkPolicy for namespace '%s':", [ns.metadata.name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-ingress",
		sprintf("  namespace: %s", [ns.metadata.name]),
		"spec:",
		"  podSelector: {}  # Empty selector matches all pods",
		"  policyTypes:",
		"  - Ingress",
		"  # No ingress rules = deny all ingress",
		"---",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-egress",
		sprintf("  namespace: %s", [ns.metadata.name]),
		"spec:",
		"  podSelector: {}",
		"  policyTypes:",
		"  - Egress",
		"  # No egress rules = deny all egress",
	]),
	ns,
	{
		"namespace": ns.metadata.name,
		"has_default_deny": "false",
	},
) if {
	ns := input.namespaces[_]
	not _is_system_namespace(ns.metadata.name)
	not _namespace_has_default_deny(ns.metadata.name)
}

results contains helpers.result_pass(
	"KC-CIS-5.3.2",
	"Ensure default deny NetworkPolicy exists per namespace",
	sprintf("Namespace '%s' has a default-deny NetworkPolicy", [ns.metadata.name]),
	ns,
) if {
	ns := input.namespaces[_]
	not _is_system_namespace(ns.metadata.name)
	_namespace_has_default_deny(ns.metadata.name)
}

# ============================================================
# Internal helpers
# ============================================================

_is_system_namespace(name) if {
	name in {"kube-system", "kube-public", "kube-node-lease"}
}

_namespace_has_netpol(ns_name) if {
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
}

# A default-deny policy has an empty podSelector and no ingress/egress rules.
_namespace_has_default_deny(ns_name) if {
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
	_is_default_deny_policy(np)
}

_is_default_deny_policy(np) if {
	# podSelector is empty (matches all pods)
	np.spec.podSelector == {}
	# Has Ingress in policyTypes but no ingress rules
	helpers.array_contains(np.spec.policyTypes, "Ingress")
	not helpers.has_key(np.spec, "ingress")
}

_is_default_deny_policy(np) if {
	np.spec.podSelector == {}
	helpers.array_contains(np.spec.policyTypes, "Egress")
	not helpers.has_key(np.spec, "egress")
}

_is_default_deny_policy(np) if {
	# podSelector with matchLabels = {} also matches all
	np.spec.podSelector.matchLabels == {}
	helpers.array_contains(np.spec.policyTypes, "Ingress")
	not helpers.has_key(np.spec, "ingress")
}

_is_default_deny_policy(np) if {
	np.spec.podSelector.matchLabels == {}
	helpers.array_contains(np.spec.policyTypes, "Egress")
	not helpers.has_key(np.spec, "egress")
}
