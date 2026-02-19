# METADATA
# title: Pod Security Standards - Baseline Profile
# description: >
#   Pod Security Standards Baseline profile checks. The Baseline
#   policy is minimally restrictive and prevents known privilege
#   escalations. It is targeted at non-critical applications.
# authors:
#   - KubeComply
# custom:
#   category: pss
#   profile: baseline
package pss.baseline

import rego.v1

import data.lib.helpers
import data.lib.kubernetes

# ============================================================
# KC-PSS-B-001: No privileged containers
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-B-001",
	"Baseline: No privileged containers",
	sprintf("Container '%s' in %s '%s/%s' runs in privileged mode", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"critical",
	concat("\n", [
		"Disable privileged mode:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      privileged: false",
	]),
	workload,
	{
		"container_name": container.name,
		"privileged": "true",
		"pss_profile": "baseline",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.is_privileged(container)
}

results contains helpers.result_pass(
	"KC-PSS-B-001",
	"Baseline: No privileged containers",
	sprintf("Container '%s' in %s '%s' is not privileged", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not kubernetes.is_privileged(container)
}

# ============================================================
# KC-PSS-B-002: No hostNetwork
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-B-002",
	"Baseline: No hostNetwork",
	sprintf("%s '%s/%s' uses hostNetwork", [
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostNetwork:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostNetwork: false",
	]),
	workload,
	{
		"hostNetwork": "true",
		"pss_profile": "baseline",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_network(pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-B-002",
	"Baseline: No hostNetwork",
	sprintf("%s '%s' does not use hostNetwork", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_network(pod_spec)
}

# ============================================================
# KC-PSS-B-003: No hostPID
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-B-003",
	"Baseline: No hostPID",
	sprintf("%s '%s/%s' uses hostPID", [
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostPID:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostPID: false",
	]),
	workload,
	{
		"hostPID": "true",
		"pss_profile": "baseline",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_pid(pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-B-003",
	"Baseline: No hostPID",
	sprintf("%s '%s' does not use hostPID", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_pid(pod_spec)
}

# ============================================================
# KC-PSS-B-004: No hostIPC
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-B-004",
	"Baseline: No hostIPC",
	sprintf("%s '%s/%s' uses hostIPC", [
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostIPC:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostIPC: false",
	]),
	workload,
	{
		"hostIPC": "true",
		"pss_profile": "baseline",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_ipc(pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-B-004",
	"Baseline: No hostIPC",
	sprintf("%s '%s' does not use hostIPC", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_ipc(pod_spec)
}

# ============================================================
# KC-PSS-B-005: No hostPath volumes
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-B-005",
	"Baseline: No hostPath volumes",
	sprintf("%s '%s/%s' uses hostPath volumes: %s", [
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
		concat(", ", hostpath_volumes),
	]),
	"high",
	concat("\n", [
		"Remove hostPath volumes and use persistent volume claims or emptyDir:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      volumes:",
		"      # REMOVE hostPath volumes:",
		"      # - name: host-vol",
		"      #   hostPath:",
		"      #     path: /data",
		"      #",
		"      # USE PersistentVolumeClaims instead:",
		"      - name: data-vol",
		"        persistentVolumeClaim:",
		"          claimName: my-pvc",
		"      # Or emptyDir for temporary storage:",
		"      - name: tmp-vol",
		"        emptyDir: {}",
	]),
	workload,
	{
		"hostPath_volumes": concat(", ", hostpath_volumes),
		"pss_profile": "baseline",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_hostpath_volume(pod_spec)
	hostpath_volumes := kubernetes.get_hostpath_volumes(pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-B-005",
	"Baseline: No hostPath volumes",
	sprintf("%s '%s' does not use hostPath volumes", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_hostpath_volume(pod_spec)
}

# ============================================================
# KC-PSS-B-006: No NodePort services (flag for review)
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-PSS-B-006",
	"Baseline: No NodePort services (review required)",
	sprintf("Service '%s/%s' uses NodePort type (port %d -> nodePort %d)", [
		object.get(svc.metadata, "namespace", "default"),
		svc.metadata.name,
		port.port,
		object.get(port, "nodePort", 0),
	]),
	"medium",
	svc,
	{
		"service_name": svc.metadata.name,
		"namespace": object.get(svc.metadata, "namespace", "default"),
		"service_type": "NodePort",
		"port": sprintf("%d", [port.port]),
		"node_port": sprintf("%d", [object.get(port, "nodePort", 0)]),
		"pss_profile": "baseline",
	},
) if {
	svc := input.services[_]
	svc.spec.type == "NodePort"
	port := svc.spec.ports[_]
}

results contains helpers.result_pass(
	"KC-PSS-B-006",
	"Baseline: No NodePort services (review required)",
	sprintf("Service '%s/%s' does not use NodePort", [
		object.get(svc.metadata, "namespace", "default"),
		svc.metadata.name,
	]),
	svc,
) if {
	svc := input.services[_]
	svc.spec.type != "NodePort"
}

# ============================================================
# Internal helpers
# ============================================================

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
