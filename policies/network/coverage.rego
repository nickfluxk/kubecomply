# METADATA
# title: NetworkPolicy Coverage Analysis
# description: >
#   Analyzes NetworkPolicy coverage across namespaces, identifying
#   gaps in ingress and egress default-deny policies.
# authors:
#   - KubeComply
# custom:
#   category: network
package network.coverage

import rego.v1

import data.lib.helpers

# ============================================================
# KC-NET-001: Overall namespace NetworkPolicy coverage percentage
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-NET-001",
	"Overall namespace NetworkPolicy coverage",
	sprintf("NetworkPolicy coverage: %d%% (%d of %d user namespaces have policies)", [
		_coverage_percentage,
		count(_namespaces_with_policies),
		count(_user_namespaces),
	]),
	_coverage_severity,
	concat("\n", [
		"Improve NetworkPolicy coverage across all namespaces.",
		"Each namespace should have at least one NetworkPolicy.",
		"",
		"# Create a default-deny policy for uncovered namespaces:",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-all",
		"  namespace: <namespace>  # Apply to each uncovered namespace",
		"spec:",
		"  podSelector: {}",
		"  policyTypes:",
		"  - Ingress",
		"  - Egress",
	]),
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
	{
		"coverage_percentage": sprintf("%d", [_coverage_percentage]),
		"covered_namespaces": sprintf("%d", [count(_namespaces_with_policies)]),
		"total_user_namespaces": sprintf("%d", [count(_user_namespaces)]),
		"uncovered_namespaces": concat(", ", _namespaces_without_policies),
	},
) if {
	count(_user_namespaces) > 0
	_coverage_percentage < 100
}

results contains helpers.result_pass(
	"KC-NET-001",
	"Overall namespace NetworkPolicy coverage",
	sprintf("NetworkPolicy coverage: 100%% (%d of %d namespaces covered)", [
		count(_namespaces_with_policies),
		count(_user_namespaces),
	]),
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
) if {
	count(_user_namespaces) > 0
	_coverage_percentage == 100
}

# ============================================================
# KC-NET-002: Namespaces without any NetworkPolicy
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-NET-002",
	"Namespaces without any NetworkPolicy",
	sprintf("Namespace '%s' has no NetworkPolicy configured", [ns_name]),
	"high",
	concat("\n", [
		sprintf("Create a NetworkPolicy for namespace '%s':", [ns_name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-all",
		sprintf("  namespace: %s", [ns_name]),
		"spec:",
		"  podSelector: {}",
		"  policyTypes:",
		"  - Ingress",
		"  - Egress",
	]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
	{
		"namespace": ns_name,
		"network_policy_count": "0",
	},
) if {
	ns_name := _namespaces_without_policies[_]
}

results contains helpers.result_pass(
	"KC-NET-002",
	"Namespaces without any NetworkPolicy",
	sprintf("Namespace '%s' has %d NetworkPolicy resource(s)", [ns_name, count(policies)]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
) if {
	ns_name := _namespaces_with_policies[_]
	policies := {np.metadata.name |
		np := input.network_policies[_]
		np.metadata.namespace == ns_name
	}
}

# ============================================================
# KC-NET-003: Namespaces without default-deny ingress policy
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-NET-003",
	"Namespaces without default-deny ingress policy",
	sprintf("Namespace '%s' lacks a default-deny ingress NetworkPolicy", [ns_name]),
	"high",
	concat("\n", [
		sprintf("Create a default-deny ingress policy for namespace '%s':", [ns_name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-ingress",
		sprintf("  namespace: %s", [ns_name]),
		"spec:",
		"  podSelector: {}  # Matches all pods in the namespace",
		"  policyTypes:",
		"  - Ingress",
		"  # No ingress rules = deny all ingress traffic",
	]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
	{
		"namespace": ns_name,
		"has_default_deny_ingress": "false",
	},
) if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	not _has_default_deny_ingress(ns_name)
}

results contains helpers.result_pass(
	"KC-NET-003",
	"Namespaces without default-deny ingress policy",
	sprintf("Namespace '%s' has a default-deny ingress policy", [ns_name]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
) if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	_has_default_deny_ingress(ns_name)
}

# ============================================================
# KC-NET-004: Namespaces without default-deny egress policy
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-NET-004",
	"Namespaces without default-deny egress policy",
	sprintf("Namespace '%s' lacks a default-deny egress NetworkPolicy", [ns_name]),
	"medium",
	concat("\n", [
		sprintf("Create a default-deny egress policy for namespace '%s':", [ns_name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		"  name: default-deny-egress",
		sprintf("  namespace: %s", [ns_name]),
		"spec:",
		"  podSelector: {}",
		"  policyTypes:",
		"  - Egress",
		"  # No egress rules = deny all egress traffic",
		"  #",
		"  # Then allow specific egress as needed:",
		"  # ---",
		"  # apiVersion: networking.k8s.io/v1",
		"  # kind: NetworkPolicy",
		"  # metadata:",
		"  #   name: allow-dns-egress",
		sprintf("  #   namespace: %s", [ns_name]),
		"  # spec:",
		"  #   podSelector: {}",
		"  #   policyTypes:",
		"  #   - Egress",
		"  #   egress:",
		"  #   - to:",
		"  #     - namespaceSelector:",
		"  #         matchLabels:",
		"  #           kubernetes.io/metadata.name: kube-system",
		"  #     ports:",
		"  #     - protocol: UDP",
		"  #       port: 53",
	]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
	{
		"namespace": ns_name,
		"has_default_deny_egress": "false",
	},
) if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	not _has_default_deny_egress(ns_name)
}

results contains helpers.result_pass(
	"KC-NET-004",
	"Namespaces without default-deny egress policy",
	sprintf("Namespace '%s' has a default-deny egress policy", [ns_name]),
	{"kind": "Namespace", "metadata": {"name": ns_name}},
) if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	_has_default_deny_egress(ns_name)
}

# ============================================================
# Internal helpers
# ============================================================

_system_namespaces := {"kube-system", "kube-public", "kube-node-lease"}

_user_namespaces contains ns if {
	ns := input.namespaces[_]
	not ns.metadata.name in _system_namespaces
}

_namespaces_with_policies contains ns_name if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
}

_namespaces_without_policies contains ns_name if {
	ns := _user_namespaces[_]
	ns_name := ns.metadata.name
	not ns_name in _namespaces_with_policies
}

_coverage_percentage := percentage if {
	count(_user_namespaces) > 0
	percentage := round((count(_namespaces_with_policies) * 100) / count(_user_namespaces))
}

_coverage_percentage := 100 if {
	count(_user_namespaces) == 0
}

_coverage_severity := "critical" if {
	_coverage_percentage < 25
}

_coverage_severity := "high" if {
	_coverage_percentage >= 25
	_coverage_percentage < 50
}

_coverage_severity := "medium" if {
	_coverage_percentage >= 50
	_coverage_percentage < 75
}

_coverage_severity := "low" if {
	_coverage_percentage >= 75
	_coverage_percentage < 100
}

# Default-deny ingress: empty podSelector, Ingress in policyTypes, no ingress rules
_has_default_deny_ingress(ns_name) if {
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
	_is_empty_selector(np.spec.podSelector)
	helpers.array_contains(np.spec.policyTypes, "Ingress")
	not helpers.has_key(np.spec, "ingress")
}

# Default-deny egress: empty podSelector, Egress in policyTypes, no egress rules
_has_default_deny_egress(ns_name) if {
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
	_is_empty_selector(np.spec.podSelector)
	helpers.array_contains(np.spec.policyTypes, "Egress")
	not helpers.has_key(np.spec, "egress")
}

_is_empty_selector(selector) if {
	selector == {}
}

_is_empty_selector(selector) if {
	object.get(selector, "matchLabels", {}) == {}
	not helpers.has_key(selector, "matchExpressions")
}
