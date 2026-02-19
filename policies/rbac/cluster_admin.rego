# METADATA
# title: RBAC Cluster Admin Analysis
# description: >
#   Deep RBAC analysis for cluster-admin role usage.
#   Inventories all bindings to the cluster-admin role and
#   flags potentially risky configurations.
# authors:
#   - KubeComply
# custom:
#   category: rbac
package rbac.cluster_admin

import rego.v1

import data.lib.helpers

# ============================================================
# KC-RBAC-001: Inventory all ClusterRoleBindings to cluster-admin
# ============================================================

# Report each ClusterRoleBinding that references cluster-admin
results contains helpers.result_warn_with_evidence(
	"KC-RBAC-001",
	"Inventory all ClusterRoleBindings to cluster-admin",
	sprintf("ClusterRoleBinding '%s' grants cluster-admin to %d subject(s): %s", [
		binding.metadata.name,
		count(binding.subjects),
		concat(", ", _subject_names(binding)),
	]),
	"high",
	binding,
	{
		"binding_name": binding.metadata.name,
		"subject_count": sprintf("%d", [count(binding.subjects)]),
		"subjects": concat("; ", _subject_details(binding)),
	},
) if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	binding.roleRef.kind == "ClusterRole"
}

# Pass when no cluster-admin bindings exist
results contains helpers.result_pass(
	"KC-RBAC-001",
	"Inventory all ClusterRoleBindings to cluster-admin",
	"No ClusterRoleBindings reference cluster-admin",
	{"kind": "ClusterRoleBinding", "metadata": {"name": "cluster-wide"}},
) if {
	count(_cluster_admin_bindings) == 0
}

_cluster_admin_bindings contains binding if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	binding.roleRef.kind == "ClusterRole"
}

# ============================================================
# KC-RBAC-002: Flag cluster-admin bindings to service accounts
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-002",
	"Flag cluster-admin bindings to service accounts",
	sprintf("Service account '%s/%s' has cluster-admin via ClusterRoleBinding '%s'", [
		object.get(subject, "namespace", "default"),
		subject.name,
		binding.metadata.name,
	]),
	"critical",
	concat("\n", [
		"Service accounts should not have cluster-admin privileges.",
		"Create a scoped ClusterRole instead:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRole",
		"metadata:",
		sprintf("  name: %s-scoped-role", [subject.name]),
		"rules:",
		"- apiGroups: [\"apps\"]",
		"  resources: [\"deployments\"]",
		"  verbs: [\"get\", \"list\", \"watch\"]",
		"---",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRoleBinding",
		"metadata:",
		sprintf("  name: %s-scoped-binding", [subject.name]),
		"roleRef:",
		"  apiGroup: rbac.authorization.k8s.io",
		"  kind: ClusterRole",
		sprintf("  name: %s-scoped-role", [subject.name]),
		"subjects:",
		"- kind: ServiceAccount",
		sprintf("  name: %s", [subject.name]),
		sprintf("  namespace: %s", [object.get(subject, "namespace", "default")]),
	]),
	binding,
	{
		"binding_name": binding.metadata.name,
		"service_account": subject.name,
		"sa_namespace": object.get(subject, "namespace", "default"),
	},
) if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	subject := binding.subjects[_]
	subject.kind == "ServiceAccount"
}

# ============================================================
# KC-RBAC-003: Flag cluster-admin bindings to groups (non-system)
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-003",
	"Flag cluster-admin bindings to non-system groups",
	sprintf("Group '%s' has cluster-admin via ClusterRoleBinding '%s'", [
		subject.name,
		binding.metadata.name,
	]),
	"critical",
	concat("\n", [
		"Review if this group truly needs cluster-admin access.",
		"Replace with a scoped role for the specific group needs:",
		"",
		"apiVersion: rbac.authorization.k8s.io/v1",
		"kind: ClusterRoleBinding",
		"metadata:",
		sprintf("  name: %s-scoped", [binding.metadata.name]),
		"roleRef:",
		"  apiGroup: rbac.authorization.k8s.io",
		"  kind: ClusterRole",
		"  name: view  # Or a custom scoped role",
		"subjects:",
		"- kind: Group",
		sprintf("  name: %s", [subject.name]),
		"  apiGroup: rbac.authorization.k8s.io",
	]),
	binding,
	{
		"binding_name": binding.metadata.name,
		"group_name": subject.name,
	},
) if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	subject := binding.subjects[_]
	subject.kind == "Group"
	not _is_system_group(subject.name)
}

_is_system_group(name) if {
	startswith(name, "system:")
}

# ============================================================
# KC-RBAC-004: Count total cluster-admin subjects
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-RBAC-004",
	"Count total cluster-admin subjects",
	sprintf("Total cluster-admin subjects: %d (Users: %d, Groups: %d, ServiceAccounts: %d)", [
		_total_subjects,
		count(_user_subjects),
		count(_group_subjects),
		count(_sa_subjects),
	]),
	_subject_count_severity,
	{"kind": "ClusterRoleBinding", "metadata": {"name": "cluster-wide"}},
	{
		"total_subjects": sprintf("%d", [_total_subjects]),
		"user_subjects": sprintf("%d", [count(_user_subjects)]),
		"group_subjects": sprintf("%d", [count(_group_subjects)]),
		"service_account_subjects": sprintf("%d", [count(_sa_subjects)]),
	},
) if {
	_total_subjects > 0
}

results contains helpers.result_pass(
	"KC-RBAC-004",
	"Count total cluster-admin subjects",
	"No subjects have cluster-admin access",
	{"kind": "ClusterRoleBinding", "metadata": {"name": "cluster-wide"}},
) if {
	_total_subjects == 0
}

# Collect all subjects bound to cluster-admin
_all_admin_subjects contains subject if {
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == "cluster-admin"
	subject := binding.subjects[_]
}

_user_subjects contains subject if {
	subject := _all_admin_subjects[_]
	subject.kind == "User"
}

_group_subjects contains subject if {
	subject := _all_admin_subjects[_]
	subject.kind == "Group"
	not _is_system_group(subject.name)
}

_sa_subjects contains subject if {
	subject := _all_admin_subjects[_]
	subject.kind == "ServiceAccount"
}

_total_subjects := count(_user_subjects) + count(_group_subjects) + count(_sa_subjects)

_subject_count_severity := "critical" if {
	_total_subjects > 10
}

_subject_count_severity := "high" if {
	_total_subjects > 5
	_total_subjects <= 10
}

_subject_count_severity := "medium" if {
	_total_subjects > 0
	_total_subjects <= 5
}

_subject_count_severity := "low" if {
	_total_subjects == 0
}

# ============================================================
# Internal helpers
# ============================================================

_subject_names(binding) := {name |
	subject := binding.subjects[_]
	name := subject.name
}

_subject_details(binding) := {detail |
	subject := binding.subjects[_]
	detail := sprintf("%s:%s", [subject.kind, subject.name])
}
