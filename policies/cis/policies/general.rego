# METADATA
# title: CIS Kubernetes Benchmark - Section 5.7 General Policies
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 5.7 checks for general
#   workload security best practices.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "5.7"
package cis.policies.general

import rego.v1

import data.lib.helpers

# ============================================================
# KC-CIS-5.7.1: Create administrative boundaries between resources using namespaces
# ============================================================

# Flag clusters with only system namespaces and default
results contains helpers.result_warn_with_evidence(
	"KC-CIS-5.7.1",
	"Create administrative boundaries between resources using namespaces",
	"Cluster has very few user-defined namespaces. Consider using namespaces to create administrative boundaries",
	"medium",
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
	{
		"total_namespaces": sprintf("%d", [count(input.namespaces)]),
		"user_namespaces": sprintf("%d", [count(_user_namespaces)]),
	},
) if {
	count(_user_namespaces) < 2
}

results contains helpers.result_pass(
	"KC-CIS-5.7.1",
	"Create administrative boundaries between resources using namespaces",
	sprintf("Cluster uses %d user-defined namespaces for administrative boundaries", [count(_user_namespaces)]),
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
) if {
	count(_user_namespaces) >= 2
}

_user_namespaces contains ns if {
	ns := input.namespaces[_]
	not _is_system_namespace(ns.metadata.name)
}

# ============================================================
# KC-CIS-5.7.2: Ensure Seccomp profile is set to docker/default or runtime/default
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.7.2",
	"Ensure Seccomp profile is set to docker/default or runtime/default",
	sprintf("Container '%s' in %s '%s' does not have a Seccomp profile configured", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Set a Seccomp profile on the container or pod:",
		"",
		"spec:",
		"  # Pod-level seccomp (applies to all containers):",
		"  securityContext:",
		"    seccompProfile:",
		"      type: RuntimeDefault",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    # Or container-level seccomp:",
		"    securityContext:",
		"      seccompProfile:",
		"        type: RuntimeDefault",
	]),
	workload,
	{
		"container_name": container.name,
		"seccomp_profile": "not set",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _has_seccomp(container, pod_spec)
}

results contains helpers.result_pass(
	"KC-CIS-5.7.2",
	"Ensure Seccomp profile is set to docker/default or runtime/default",
	sprintf("Container '%s' in %s '%s' has a Seccomp profile configured", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_has_seccomp(container, pod_spec)
}

# ============================================================
# KC-CIS-5.7.3: Apply AppArmor profile to containers
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.7.3",
	"Apply AppArmor profile to containers",
	sprintf("Container '%s' in %s '%s' does not have an AppArmor profile", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Apply an AppArmor profile annotation to the pod:",
		"",
		"metadata:",
		"  annotations:",
		sprintf("    container.apparmor.security.beta.kubernetes.io/%s: runtime/default", [container.name]),
		"",
		"# Or use the securityContext (Kubernetes 1.30+):",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      appArmorProfile:",
		"        type: RuntimeDefault",
	]),
	workload,
	{
		"container_name": container.name,
		"apparmor_profile": "not set",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _has_apparmor(workload, container)
}

results contains helpers.result_pass(
	"KC-CIS-5.7.3",
	"Apply AppArmor profile to containers",
	sprintf("Container '%s' in %s '%s' has an AppArmor profile applied", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_has_apparmor(workload, container)
}

# ============================================================
# KC-CIS-5.7.4: Ensure default namespace is not used
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.7.4",
	"Ensure default namespace is not used",
	sprintf("%s '%s' is deployed in the default namespace", [
		workload.kind,
		workload.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Move resources out of the default namespace:",
		"",
		"# Create a dedicated namespace:",
		"kubectl create namespace my-app",
		"",
		"# Redeploy in the new namespace:",
		sprintf("apiVersion: %s", [object.get(workload, "apiVersion", "apps/v1")]),
		sprintf("kind: %s", [workload.kind]),
		"metadata:",
		sprintf("  name: %s", [workload.metadata.name]),
		"  namespace: my-app  # Use a dedicated namespace",
	]),
	workload,
	{
		"resource_kind": workload.kind,
		"resource_name": workload.metadata.name,
		"namespace": "default",
	},
) if {
	workload := _all_workloads[_]
	_in_default_namespace(workload)
}

results contains helpers.result_pass(
	"KC-CIS-5.7.4",
	"Ensure default namespace is not used",
	sprintf("%s '%s' is in namespace '%s' (not default)", [
		workload.kind,
		workload.metadata.name,
		workload.metadata.namespace,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	not _in_default_namespace(workload)
}

# ============================================================
# Internal helpers
# ============================================================

_is_system_namespace(name) if {
	name in {"kube-system", "kube-public", "kube-node-lease", "default"}
}

_all_workloads contains w if {
	w := input.pods[_]
}

_all_workloads contains w if {
	w := input.deployments[_]
}

_has_seccomp(container, _) if {
	container.securityContext.seccompProfile.type
}

_has_seccomp(_, pod_spec) if {
	pod_spec.securityContext.seccompProfile.type
}

_has_apparmor(workload, container) if {
	annotation_key := sprintf("container.apparmor.security.beta.kubernetes.io/%s", [container.name])
	workload.metadata.annotations[annotation_key]
}

# Kubernetes 1.30+ supports appArmorProfile in securityContext
_has_apparmor(_, container) if {
	container.securityContext.appArmorProfile.type
}

_in_default_namespace(workload) if {
	workload.metadata.namespace == "default"
}

_in_default_namespace(workload) if {
	not helpers.has_key(workload.metadata, "namespace")
}
