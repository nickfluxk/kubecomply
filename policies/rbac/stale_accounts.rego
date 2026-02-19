# METADATA
# title: RBAC Stale Accounts Analysis
# description: >
#   Identifies stale, orphaned, or unused RBAC resources including
#   roles with no bindings, bindings referencing non-existent roles,
#   and service accounts not used by any pods.
# authors:
#   - KubeComply
# custom:
#   category: rbac
package rbac.stale_accounts

import rego.v1

import data.lib.helpers

# ============================================================
# KC-RBAC-020: Identify roles with zero bindings (orphaned roles)
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-RBAC-020",
	"Identify roles with zero bindings (orphaned roles)",
	sprintf("%s '%s'%s has no bindings and may be unused", [
		role.kind,
		role.metadata.name,
		_namespace_suffix(role),
	]),
	"low",
	role,
	{
		"role_kind": role.kind,
		"role_name": role.metadata.name,
		"namespace": object.get(object.get(role, "metadata", {}), "namespace", ""),
		"binding_count": "0",
		"remediation": concat("\n", [
			sprintf("Review and remove the orphaned %s if no longer needed:", [role.kind]),
			"",
			sprintf("# Check if the role is still needed:", []),
			sprintf("kubectl describe %s %s%s", [
				lower(role.kind),
				role.metadata.name,
				_kubectl_namespace_flag(role),
			]),
			"",
			sprintf("# Delete if no longer needed:", []),
			sprintf("kubectl delete %s %s%s", [
				lower(role.kind),
				role.metadata.name,
				_kubectl_namespace_flag(role),
			]),
		]),
	},
) if {
	role := _all_non_system_roles[_]
	not _role_has_binding(role)
}

# ============================================================
# KC-RBAC-021: Identify RoleBindings referencing non-existent roles
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-RBAC-021",
	"Identify RoleBindings referencing non-existent roles",
	sprintf("%s '%s'%s references non-existent %s '%s'", [
		binding.kind,
		binding.metadata.name,
		_namespace_suffix(binding),
		binding.roleRef.kind,
		binding.roleRef.name,
	]),
	"medium",
	concat("\n", [
		"This binding references a role that does not exist.",
		"Either create the missing role or remove the stale binding:",
		"",
		sprintf("# Remove the stale binding:", []),
		sprintf("kubectl delete %s %s%s", [
			lower(binding.kind),
			binding.metadata.name,
			_kubectl_namespace_flag(binding),
		]),
		"",
		"# Or create the missing role:",
		"apiVersion: rbac.authorization.k8s.io/v1",
		sprintf("kind: %s", [binding.roleRef.kind]),
		"metadata:",
		sprintf("  name: %s", [binding.roleRef.name]),
		"rules:",
		"- apiGroups: [\"\"]",
		"  resources: [\"pods\"]",
		"  verbs: [\"get\", \"list\"]",
	]),
	binding,
	{
		"binding_kind": binding.kind,
		"binding_name": binding.metadata.name,
		"referenced_role_kind": binding.roleRef.kind,
		"referenced_role_name": binding.roleRef.name,
	},
) if {
	binding := _all_bindings[_]
	not _referenced_role_exists(binding)
}

# ============================================================
# KC-RBAC-022: Identify service accounts with no pods using them
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-RBAC-022",
	"Identify service accounts with no pods using them",
	sprintf("ServiceAccount '%s/%s' is not used by any pods", [
		sa.metadata.namespace,
		sa.metadata.name,
	]),
	"low",
	sa,
	{
		"service_account": sa.metadata.name,
		"namespace": sa.metadata.namespace,
		"pod_count": "0",
		"remediation": concat("\n", [
			"Review and remove unused service accounts:",
			"",
			sprintf("# Verify no workloads use this service account:", []),
			sprintf("kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.serviceAccountName == \"%s\" and .metadata.namespace == \"%s\")'", [
				sa.metadata.name,
				sa.metadata.namespace,
			]),
			"",
			sprintf("# Delete if confirmed unused:", []),
			sprintf("kubectl delete serviceaccount %s -n %s", [
				sa.metadata.name,
				sa.metadata.namespace,
			]),
		]),
	},
) if {
	sa := input.service_accounts[_]
	sa.metadata.name != "default"
	not _is_system_sa(sa)
	not _sa_used_by_pod(sa)
}

results contains helpers.result_pass(
	"KC-RBAC-022",
	"Identify service accounts with no pods using them",
	sprintf("ServiceAccount '%s/%s' is actively used by pods", [
		sa.metadata.namespace,
		sa.metadata.name,
	]),
	sa,
) if {
	sa := input.service_accounts[_]
	sa.metadata.name != "default"
	not _is_system_sa(sa)
	_sa_used_by_pod(sa)
}

# ============================================================
# Internal helpers
# ============================================================

# All non-system roles (both namespaced and cluster-scoped)
_all_non_system_roles contains role if {
	role := input.cluster_roles[_]
	not _is_system_role(role)
}

_all_non_system_roles contains role if {
	role := input.roles[_]
	not _is_system_role(role)
}

_is_system_role(role) if {
	startswith(role.metadata.name, "system:")
}

_is_system_role(role) if {
	role.metadata.labels["kubernetes.io/bootstrapping"] == "rbac-defaults"
}

# Check if a role has at least one binding
_role_has_binding(role) if {
	role.kind == "ClusterRole"
	binding := input.cluster_role_bindings[_]
	binding.roleRef.name == role.metadata.name
	binding.roleRef.kind == "ClusterRole"
}

_role_has_binding(role) if {
	role.kind == "ClusterRole"
	binding := input.role_bindings[_]
	binding.roleRef.name == role.metadata.name
	binding.roleRef.kind == "ClusterRole"
}

_role_has_binding(role) if {
	role.kind == "Role"
	binding := input.role_bindings[_]
	binding.metadata.namespace == role.metadata.namespace
	binding.roleRef.name == role.metadata.name
	binding.roleRef.kind == "Role"
}

# All bindings (cluster and namespaced)
_all_bindings contains binding if {
	binding := input.cluster_role_bindings[_]
}

_all_bindings contains binding if {
	binding := input.role_bindings[_]
}

# Check if the role referenced by a binding exists
_referenced_role_exists(binding) if {
	binding.roleRef.kind == "ClusterRole"
	role := input.cluster_roles[_]
	role.metadata.name == binding.roleRef.name
}

_referenced_role_exists(binding) if {
	binding.roleRef.kind == "Role"
	role := input.roles[_]
	role.metadata.namespace == binding.metadata.namespace
	role.metadata.name == binding.roleRef.name
}

# Check if a service account is used by any pod
_sa_used_by_pod(sa) if {
	pod := input.pods[_]
	pod.metadata.namespace == sa.metadata.namespace
	pod.spec.serviceAccountName == sa.metadata.name
}

_is_system_sa(sa) if {
	sa.metadata.namespace in {"kube-system", "kube-public", "kube-node-lease"}
}

# Display helpers
_namespace_suffix(resource) := sprintf(" in namespace '%s'", [resource.metadata.namespace]) if {
	helpers.has_key(resource.metadata, "namespace")
}

_namespace_suffix(resource) := "" if {
	not helpers.has_key(resource.metadata, "namespace")
}

_kubectl_namespace_flag(resource) := sprintf(" -n %s", [resource.metadata.namespace]) if {
	helpers.has_key(resource.metadata, "namespace")
}

_kubectl_namespace_flag(resource) := "" if {
	not helpers.has_key(resource.metadata, "namespace")
}
