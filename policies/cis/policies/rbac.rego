# METADATA
# title: CIS Kubernetes Benchmark - Section 5.1 RBAC
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 5.1 checks for RBAC
#   and Service Accounts configuration.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "5.1"
package cis.policies.rbac

import rego.v1

import data.lib.helpers
import data.lib.kubernetes

# ============================================================
# KC-CIS-5.1.1: Ensure cluster-admin role is only used where required
# ============================================================

# Find all ClusterRoleBindings that reference cluster-admin
results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.1",
	"Ensure cluster-admin role is only used where required",
	sprintf("ClusterRoleBinding '%s' grants cluster-admin to subject '%s' (kind: %s)", [
		binding.metadata.name,
		subject.name,
		subject.kind,
	]),
	"critical",
	concat("\n", [
		"Review and minimize cluster-admin usage. Replace with scoped roles:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRole",
		"metadata:",
		"  name: limited-admin",
		"rules:",
		"- apiGroups: [\"apps\"]",
		"  resources: [\"deployments\", \"statefulsets\"]",
		"  verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\"]",
		"---",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRoleBinding",
		"metadata:",
		sprintf("  name: %s-replacement", [binding.metadata.name]),
		"roleRef:",
		"  apiGroup: rbac.authorization.k8s.io",
		"  kind: ClusterRole",
		"  name: limited-admin",
		"subjects:",
		sprintf("- kind: %s", [subject.kind]),
		sprintf("  name: %s", [subject.name]),
	]),
	binding,
	{
		"binding_name": binding.metadata.name,
		"subject_kind": subject.kind,
		"subject_name": subject.name,
		"role_ref": "cluster-admin",
	},
) if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	subject := binding.subjects[_]

	# Exclude system bindings that are expected
	not _is_system_binding(binding)
}

# Pass result when no non-system cluster-admin bindings exist
results contains helpers.result_pass(
	"KC-CIS-5.1.1",
	"Ensure cluster-admin role is only used where required",
	"No non-system ClusterRoleBindings grant cluster-admin",
	{"kind": "ClusterRoleBinding", "metadata": {"name": "cluster-wide"}},
) if {
	count(_non_system_cluster_admin_bindings) == 0
}

_non_system_cluster_admin_bindings contains binding if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	not _is_system_binding(binding)
}

_is_system_binding(binding) if {
	startswith(binding.metadata.name, "system:")
}

_is_system_binding(binding) if {
	binding.metadata.labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}

# ============================================================
# KC-CIS-5.1.2: Minimize access to secrets
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.2",
	"Minimize access to secrets",
	sprintf("%s '%s' grants '%s' access to secrets", [
		role.kind,
		role.metadata.name,
		verb,
	]),
	"high",
	concat("\n", [
		"Remove broad secret access. Scope to specific secrets if needed:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		"- apiGroups: [\"\"]",
		"  resources: [\"secrets\"]",
		"  resourceNames: [\"specific-secret-name\"]  # Scope to specific secrets",
		"  verbs: [\"get\"]  # Minimize verbs",
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"verb": verb,
		"rule_index": i,
	},
) if {
	role := _all_roles[_]
	rule := role.rules[i]
	_rule_targets_secrets(rule)
	verb := rule.verbs[_]
	verb in {"get", "list", "watch", "*"}
	not _has_resource_names(rule)
}

_all_roles contains role if {
	role := input.cluster_roles[_]
}

_all_roles contains role if {
	role := input.roles[_]
}

_rule_targets_secrets(rule) if {
	rule.apiGroups[_] in {"", "*"}
	rule.resources[_] in {"secrets", "*"}
}

_has_resource_names(rule) if {
	count(rule.resourceNames) > 0
}

# ============================================================
# KC-CIS-5.1.3: Minimize wildcard use in Roles and ClusterRoles
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.3",
	"Minimize wildcard use in Roles and ClusterRoles",
	sprintf("%s '%s' uses wildcard in %s at rule index %d", [
		role.kind,
		role.metadata.name,
		wildcard_field,
		i,
	]),
	"high",
	concat("\n", [
		"Replace wildcard access with specific resources and verbs:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		"- apiGroups: [\"apps\"]           # Specific API group, not '*'",
		"  resources: [\"deployments\"]    # Specific resources, not '*'",
		"  verbs: [\"get\", \"list\"]       # Specific verbs, not '*'",
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"wildcard_field": wildcard_field,
		"rule_index": i,
	},
) if {
	role := _all_roles[_]
	rule := role.rules[i]
	wildcard_field := _wildcard_field(rule)
}

_wildcard_field(rule) := "verbs" if {
	rule.verbs[_] == "*"
}

_wildcard_field(rule) := "resources" if {
	rule.resources[_] == "*"
}

_wildcard_field(rule) := "apiGroups" if {
	rule.apiGroups[_] == "*"
}

# ============================================================
# KC-CIS-5.1.4: Minimize access to create pods
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.4",
	"Minimize access to create pods",
	sprintf("%s '%s' grants pod creation access", [
		role.kind,
		role.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Remove direct pod creation privileges. Use Deployments/StatefulSets instead:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		sprintf("kind: %s", [role.kind]),
		"metadata:",
		sprintf("  name: %s", [role.metadata.name]),
		"rules:",
		"- apiGroups: [\"apps\"]",
		"  resources: [\"deployments\"]",
		"  verbs: [\"create\", \"update\", \"patch\"]  # Use workload controllers, not bare pods",
	]),
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
	},
) if {
	role := _all_roles[_]
	rule := role.rules[_]
	rule.apiGroups[_] in {"", "*"}
	rule.resources[_] in {"pods", "*"}
	rule.verbs[_] in {"create", "*"}
}

# ============================================================
# KC-CIS-5.1.5: Ensure default service accounts are not actively used
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.5",
	"Ensure default service accounts are not actively used",
	sprintf("Default service account in namespace '%s' has automountServiceAccountToken enabled", [
		sa.metadata.namespace,
	]),
	"medium",
	concat("\n", [
		"Disable automount on default service accounts:",
		"",
		"apiVersion: v1",
		"kind: ServiceAccount",
		"metadata:",
		"  name: default",
		sprintf("  namespace: %s", [sa.metadata.namespace]),
		"automountServiceAccountToken: false",
	]),
	sa,
	{
		"service_account": "default",
		"namespace": sa.metadata.namespace,
		"automount": "true",
	},
) if {
	sa := input.service_accounts[_]
	sa.metadata.name == "default"
	_sa_has_automount(sa)
}

_sa_has_automount(sa) if {
	sa.automountServiceAccountToken == true
}

_sa_has_automount(sa) if {
	not helpers.has_key(sa, "automountServiceAccountToken")
}

# Pass for default SA with automount disabled
results contains helpers.result_pass(
	"KC-CIS-5.1.5",
	"Ensure default service accounts are not actively used",
	sprintf("Default service account in namespace '%s' has automountServiceAccountToken disabled", [
		sa.metadata.namespace,
	]),
	sa,
) if {
	sa := input.service_accounts[_]
	sa.metadata.name == "default"
	sa.automountServiceAccountToken == false
}

# ============================================================
# KC-CIS-5.1.6: Ensure service account tokens are not mounted where unnecessary
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.1.6",
	"Ensure service account tokens are not mounted where unnecessary",
	sprintf("Workload '%s' in namespace '%s' auto-mounts service account token", [
		workload.metadata.name,
		object.get(workload.metadata, "namespace", "default"),
	]),
	"medium",
	concat("\n", [
		"Disable automatic mounting of service account tokens:",
		"",
		sprintf("apiVersion: %s", [workload.apiVersion]),
		sprintf("kind: %s", [workload.kind]),
		"metadata:",
		sprintf("  name: %s", [workload.metadata.name]),
		"spec:",
		"  template:",
		"    spec:",
		"      automountServiceAccountToken: false  # Add this line",
	]),
	workload,
	{
		"workload_kind": workload.kind,
		"workload_name": workload.metadata.name,
		"namespace": object.get(workload.metadata, "namespace", "default"),
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_automount_sa_token(pod_spec)
}

_all_workloads contains w if {
	w := input.pods[_]
}

_all_workloads contains w if {
	w := input.deployments[_]
}

_all_workloads contains w if {
	w := input.daemonsets[_]
}

_all_workloads contains w if {
	w := input.statefulsets[_]
}
