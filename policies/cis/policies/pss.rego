# METADATA
# title: CIS Kubernetes Benchmark - Section 5.2 Pod Security
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 5.2 checks for Pod Security
#   Standards compliance.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "5.2"
package cis.policies.pss

import rego.v1

import data.lib.helpers
import data.lib.kubernetes

# ============================================================
# KC-CIS-5.2.1: Minimize admission of privileged containers
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.1",
	"Minimize admission of privileged containers",
	sprintf("Container '%s' in %s '%s' runs in privileged mode", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"critical",
	concat("\n", [
		"Disable privileged mode on the container:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      privileged: false  # Change from true to false",
	]),
	workload,
	{
		"container_name": container.name,
		"privileged": "true",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.is_privileged(container)
}

# Pass for non-privileged containers
results contains helpers.result_pass(
	"KC-CIS-5.2.1",
	"Minimize admission of privileged containers",
	sprintf("Container '%s' in %s '%s' does not run privileged", [
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
# KC-CIS-5.2.2: Minimize admission of containers wishing to share host PID
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.2",
	"Minimize admission of containers wishing to share host PID namespace",
	sprintf("%s '%s' has hostPID enabled", [
		workload.kind,
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostPID:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostPID: false  # Remove or set to false",
	]),
	workload,
	{"hostPID": "true"},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_pid(pod_spec)
}

results contains helpers.result_pass(
	"KC-CIS-5.2.2",
	"Minimize admission of containers wishing to share host PID namespace",
	sprintf("%s '%s' does not use hostPID", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_pid(pod_spec)
}

# ============================================================
# KC-CIS-5.2.3: Minimize admission of containers wishing to share host IPC
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.3",
	"Minimize admission of containers wishing to share host IPC namespace",
	sprintf("%s '%s' has hostIPC enabled", [
		workload.kind,
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostIPC:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostIPC: false  # Remove or set to false",
	]),
	workload,
	{"hostIPC": "true"},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_ipc(pod_spec)
}

results contains helpers.result_pass(
	"KC-CIS-5.2.3",
	"Minimize admission of containers wishing to share host IPC namespace",
	sprintf("%s '%s' does not use hostIPC", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_ipc(pod_spec)
}

# ============================================================
# KC-CIS-5.2.4: Minimize admission of containers wishing to share host network
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.4",
	"Minimize admission of containers wishing to share host network namespace",
	sprintf("%s '%s' has hostNetwork enabled", [
		workload.kind,
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Disable hostNetwork:",
		"",
		"spec:",
		"  template:",
		"    spec:",
		"      hostNetwork: false  # Remove or set to false",
	]),
	workload,
	{"hostNetwork": "true"},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	kubernetes.has_host_network(pod_spec)
}

results contains helpers.result_pass(
	"KC-CIS-5.2.4",
	"Minimize admission of containers wishing to share host network namespace",
	sprintf("%s '%s' does not use hostNetwork", [workload.kind, workload.metadata.name]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	not kubernetes.has_host_network(pod_spec)
}

# ============================================================
# KC-CIS-5.2.5: Minimize admission of containers with allowPrivilegeEscalation
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.5",
	"Minimize admission of containers with allowPrivilegeEscalation",
	sprintf("Container '%s' in %s '%s' allows privilege escalation", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Explicitly disallow privilege escalation:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      allowPrivilegeEscalation: false  # Must be explicitly set to false",
	]),
	workload,
	{"container_name": container.name, "allowPrivilegeEscalation": "true"},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.allows_privilege_escalation(container)
}

# ============================================================
# KC-CIS-5.2.6: Minimize admission of root containers
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.6",
	"Minimize admission of root containers",
	sprintf("Container '%s' in %s '%s' may run as root", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Configure container to run as non-root:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      runAsNonRoot: true",
		"      runAsUser: 1000    # Use a non-root UID",
		"      runAsGroup: 1000   # Use a non-root GID",
	]),
	workload,
	{"container_name": container.name, "runs_as_root": "true"},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.runs_as_root(container)
}

results contains helpers.result_pass(
	"KC-CIS-5.2.6",
	"Minimize admission of root containers",
	sprintf("Container '%s' in %s '%s' runs as non-root", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not kubernetes.runs_as_root(container)
}

# ============================================================
# KC-CIS-5.2.7: Minimize admission of containers with added capabilities
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.7",
	"Minimize admission of containers with added capabilities",
	sprintf("Container '%s' in %s '%s' adds capabilities: %s", [
		container.name,
		workload.kind,
		workload.metadata.name,
		concat(", ", added_caps),
	]),
	"medium",
	concat("\n", [
		"Remove added capabilities and drop all instead:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      capabilities:",
		"        drop:",
		"        - ALL",
		"        # Only add back specific caps if absolutely required:",
		"        # add:",
		"        # - NET_BIND_SERVICE",
	]),
	workload,
	{
		"container_name": container.name,
		"added_capabilities": concat(", ", added_caps),
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	added_caps := {cap | cap := container.securityContext.capabilities.add[_]}
	count(added_caps) > 0
}

# ============================================================
# KC-CIS-5.2.8: Minimize admission of containers with dangerous capabilities
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.2.8",
	"Minimize admission of containers with dangerous capabilities (NET_RAW, SYS_ADMIN)",
	sprintf("Container '%s' in %s '%s' has dangerous capabilities: %s", [
		container.name,
		workload.kind,
		workload.metadata.name,
		concat(", ", dangerous_caps),
	]),
	"critical",
	concat("\n", [
		"Remove dangerous capabilities immediately:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      capabilities:",
		"        drop:",
		"        - ALL     # Drop all capabilities",
		"        # Do NOT add NET_RAW or SYS_ADMIN",
	]),
	workload,
	{
		"container_name": container.name,
		"dangerous_capabilities": concat(", ", dangerous_caps),
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	dangerous_caps := kubernetes.get_critical_caps(container)
	count(dangerous_caps) > 0
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
