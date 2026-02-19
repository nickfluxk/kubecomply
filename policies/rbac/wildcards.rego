# METADATA
# title: RBAC Wildcard Analysis
# description: >
#   Identifies and scores wildcard usage in Roles and ClusterRoles.
#   Wildcards grant overly broad permissions and should be replaced
#   with specific resource/verb/apiGroup selections.
# authors:
#   - KubeComply
# custom:
#   category: rbac
package rbac.wildcards

import rego.v1

import data.lib.helpers

# ============================================================
# KC-RBAC-010: Identify ClusterRoles with wildcard (*) verbs
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-010",
	"Identify ClusterRoles with wildcard verbs",
	sprintf("%s '%s' has wildcard (*) verbs at rule index %d", [
		role.kind,
		role.metadata.name,
		i,
	]),
	"high",
	concat("\n", [
		"Replace wildcard verbs with specific verb list:",
		"",
		sprintf("apiVersion: rbac.authorization.k8s.io/v1", []),
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		sprintf("- apiGroups: %s", [_format_list(rule.apiGroups)]),
		sprintf("  resources: %s", [_format_list(rule.resources)]),
		"  verbs: [\"get\", \"list\", \"watch\"]  # Replace '*' with specific verbs",
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"rule_index": sprintf("%d", [i]),
		"api_groups": concat(", ", rule.apiGroups),
		"resources": concat(", ", rule.resources),
	},
) if {
	role := _all_roles[_]
	rule := role.rules[i]
	rule.verbs[_] == "*"
}

# ============================================================
# KC-RBAC-011: Identify ClusterRoles with wildcard (*) resources
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-011",
	"Identify ClusterRoles with wildcard resources",
	sprintf("%s '%s' has wildcard (*) resources at rule index %d", [
		role.kind,
		role.metadata.name,
		i,
	]),
	"high",
	concat("\n", [
		"Replace wildcard resources with specific resource types:",
		"",
		sprintf("apiVersion: rbac.authorization.k8s.io/v1", []),
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		sprintf("- apiGroups: %s", [_format_list(rule.apiGroups)]),
		"  resources: [\"pods\", \"services\", \"deployments\"]  # Replace '*' with specific resources",
		sprintf("  verbs: %s", [_format_list(rule.verbs)]),
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"rule_index": sprintf("%d", [i]),
		"api_groups": concat(", ", rule.apiGroups),
		"verbs": concat(", ", rule.verbs),
	},
) if {
	role := _all_roles[_]
	rule := role.rules[i]
	rule.resources[_] == "*"
}

# ============================================================
# KC-RBAC-012: Identify ClusterRoles with wildcard (*) API groups
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-012",
	"Identify ClusterRoles with wildcard API groups",
	sprintf("%s '%s' has wildcard (*) API groups at rule index %d", [
		role.kind,
		role.metadata.name,
		i,
	]),
	"high",
	concat("\n", [
		"Replace wildcard API groups with specific API group names:",
		"",
		sprintf("apiVersion: rbac.authorization.k8s.io/v1", []),
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		"- apiGroups: [\"\", \"apps\", \"batch\"]  # Replace '*' with specific API groups",
		sprintf("  resources: %s", [_format_list(rule.resources)]),
		sprintf("  verbs: %s", [_format_list(rule.verbs)]),
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"rule_index": sprintf("%d", [i]),
		"resources": concat(", ", rule.resources),
		"verbs": concat(", ", rule.verbs),
	},
) if {
	role := _all_roles[_]
	rule := role.rules[i]
	rule.apiGroups[_] == "*"
}

# ============================================================
# KC-RBAC-013: Score overall wildcard usage
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-013",
	"Score overall wildcard usage",
	sprintf("Total wildcard usage across all roles: %d occurrences in %d roles", [
		_total_wildcard_count,
		count(_roles_with_wildcards),
	]),
	_wildcard_score_severity,
	concat("\n", [
		"Review and eliminate wildcard permissions across all roles.",
		"Each wildcard grants broader access than typically needed.",
		"",
		"Audit strategy:",
		"1. List all roles with wildcards: kubectl get clusterroles -o json | jq '.items[] | select(.rules[]?.verbs[]? == \"*\") | .metadata.name'",
		"2. For each role, determine actual access requirements",
		"3. Replace wildcards with specific resources/verbs/apiGroups",
	]),
	{"kind": "ClusterRole", "metadata": {"name": "cluster-wide"}},
	{
		"total_wildcard_occurrences": sprintf("%d", [_total_wildcard_count]),
		"roles_with_wildcards": sprintf("%d", [count(_roles_with_wildcards)]),
		"wildcard_verbs": sprintf("%d", [_verb_wildcard_count]),
		"wildcard_resources": sprintf("%d", [_resource_wildcard_count]),
		"wildcard_api_groups": sprintf("%d", [_api_group_wildcard_count]),
	},
) if {
	_total_wildcard_count > 0
}

results contains helpers.result_pass(
	"KC-RBAC-013",
	"Score overall wildcard usage",
	"No wildcard usage found in any roles",
	{"kind": "ClusterRole", "metadata": {"name": "cluster-wide"}},
) if {
	_total_wildcard_count == 0
}

# ============================================================
# Internal helpers
# ============================================================

_all_roles contains role if {
	role := input.cluster_roles[_]
	not _is_system_role(role)
}

_all_roles contains role if {
	role := input.roles[_]
}

_is_system_role(role) if {
	startswith(role.metadata.name, "system:")
}

_roles_with_wildcards contains role.metadata.name if {
	role := _all_roles[_]
	rule := role.rules[_]
	_has_any_wildcard(rule)
}

_has_any_wildcard(rule) if {
	rule.verbs[_] == "*"
}

_has_any_wildcard(rule) if {
	rule.resources[_] == "*"
}

_has_any_wildcard(rule) if {
	rule.apiGroups[_] == "*"
}

# Count wildcards by type
_verb_wildcard_count := count({sprintf("%s/%d", [role.metadata.name, i]) |
	role := _all_roles[_]
	rule := role.rules[i]
	rule.verbs[_] == "*"
})

_resource_wildcard_count := count({sprintf("%s/%d", [role.metadata.name, i]) |
	role := _all_roles[_]
	rule := role.rules[i]
	rule.resources[_] == "*"
})

_api_group_wildcard_count := count({sprintf("%s/%d", [role.metadata.name, i]) |
	role := _all_roles[_]
	rule := role.rules[i]
	rule.apiGroups[_] == "*"
})

_total_wildcard_count := _verb_wildcard_count + _resource_wildcard_count + _api_group_wildcard_count

_wildcard_score_severity := "critical" if {
	_total_wildcard_count > 20
}

_wildcard_score_severity := "high" if {
	_total_wildcard_count > 10
	_total_wildcard_count <= 20
}

_wildcard_score_severity := "medium" if {
	_total_wildcard_count > 0
	_total_wildcard_count <= 10
}

_wildcard_score_severity := "low" if {
	_total_wildcard_count == 0
}

# Format a list of strings for display in YAML
_format_list(items) := sprintf("[\"%s\"]", [concat("\", \"", items)])
