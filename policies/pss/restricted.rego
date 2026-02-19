# METADATA
# title: Pod Security Standards - Restricted Profile
# description: >
#   Pod Security Standards Restricted profile checks. The Restricted
#   policy is heavily restricted and follows current pod hardening
#   best practices. It is targeted at security-critical applications
#   and lower-trust tenants.
# authors:
#   - KubeComply
# custom:
#   category: pss
#   profile: restricted
package pss.restricted

import rego.v1

import data.lib.helpers
import data.lib.kubernetes

# ============================================================
# KC-PSS-R-001: Must run as non-root
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-R-001",
	"Restricted: Must run as non-root",
	sprintf("Container '%s' in %s '%s/%s' does not enforce non-root execution", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Configure the container to run as non-root:",
		"",
		"spec:",
		"  # Pod-level security context (applies to all containers):",
		"  securityContext:",
		"    runAsNonRoot: true",
		"    runAsUser: 1000",
		"    runAsGroup: 1000",
		"    fsGroup: 1000",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      runAsNonRoot: true",
		"      runAsUser: 1000",
	]),
	workload,
	{
		"container_name": container.name,
		"runAsNonRoot": _get_run_as_non_root(container),
		"runAsUser": _get_run_as_user(container),
		"pss_profile": "restricted",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _container_runs_non_root(container, pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-R-001",
	"Restricted: Must run as non-root",
	sprintf("Container '%s' in %s '%s' enforces non-root execution", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_container_runs_non_root(container, pod_spec)
}

# ============================================================
# KC-PSS-R-002: Must drop ALL capabilities
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-R-002",
	"Restricted: Must drop ALL capabilities",
	sprintf("Container '%s' in %s '%s/%s' does not drop ALL capabilities", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Drop all capabilities and only add back those strictly required:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      capabilities:",
		"        drop:",
		"        - ALL",
		"        # Only add back if absolutely necessary:",
		"        # add:",
		"        # - NET_BIND_SERVICE",
	]),
	workload,
	{
		"container_name": container.name,
		"drops_all": "false",
		"pss_profile": "restricted",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not kubernetes.drops_all_capabilities(container)
}

results contains helpers.result_pass(
	"KC-PSS-R-002",
	"Restricted: Must drop ALL capabilities",
	sprintf("Container '%s' in %s '%s' drops ALL capabilities", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.drops_all_capabilities(container)
}

# ============================================================
# KC-PSS-R-003: Must set readOnlyRootFilesystem
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-R-003",
	"Restricted: Must set readOnlyRootFilesystem",
	sprintf("Container '%s' in %s '%s/%s' does not use a read-only root filesystem", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Set readOnlyRootFilesystem to true and use emptyDir for writable paths:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      readOnlyRootFilesystem: true",
		"    volumeMounts:",
		"    - name: tmp",
		"      mountPath: /tmp",
		"    - name: var-run",
		"      mountPath: /var/run",
		"  volumes:",
		"  - name: tmp",
		"    emptyDir: {}",
		"  - name: var-run",
		"    emptyDir: {}",
	]),
	workload,
	{
		"container_name": container.name,
		"readOnlyRootFilesystem": "false",
		"pss_profile": "restricted",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not kubernetes.has_read_only_root_fs(container)
}

results contains helpers.result_pass(
	"KC-PSS-R-003",
	"Restricted: Must set readOnlyRootFilesystem",
	sprintf("Container '%s' in %s '%s' uses read-only root filesystem", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	kubernetes.has_read_only_root_fs(container)
}

# ============================================================
# KC-PSS-R-004: Must set seccompProfile to RuntimeDefault or Localhost
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-R-004",
	"Restricted: Must set seccompProfile to RuntimeDefault or Localhost",
	sprintf("Container '%s' in %s '%s/%s' does not have an appropriate seccomp profile", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
		workload.metadata.name,
	]),
	"high",
	concat("\n", [
		"Set seccompProfile to RuntimeDefault or Localhost:",
		"",
		"spec:",
		"  securityContext:",
		"    seccompProfile:",
		"      type: RuntimeDefault  # Or Localhost with localhostProfile",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    securityContext:",
		"      seccompProfile:",
		"        type: RuntimeDefault",
	]),
	workload,
	{
		"container_name": container.name,
		"seccomp_type": _get_seccomp_type(container, pod_spec),
		"pss_profile": "restricted",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _has_valid_seccomp(container, pod_spec)
}

results contains helpers.result_pass(
	"KC-PSS-R-004",
	"Restricted: Must set seccompProfile to RuntimeDefault or Localhost",
	sprintf("Container '%s' in %s '%s' has valid seccomp profile", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_has_valid_seccomp(container, pod_spec)
}

# ============================================================
# KC-PSS-R-005: No privilege escalation allowed
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-PSS-R-005",
	"Restricted: No privilege escalation allowed",
	sprintf("Container '%s' in %s '%s/%s' allows privilege escalation", [
		container.name,
		workload.kind,
		object.get(workload.metadata, "namespace", "default"),
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
		"      allowPrivilegeEscalation: false",
	]),
	workload,
	{
		"container_name": container.name,
		"allowPrivilegeEscalation": "true or not set",
		"pss_profile": "restricted",
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _explicitly_denies_privilege_escalation(container)
}

results contains helpers.result_pass(
	"KC-PSS-R-005",
	"Restricted: No privilege escalation allowed",
	sprintf("Container '%s' in %s '%s' denies privilege escalation", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_explicitly_denies_privilege_escalation(container)
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

# Check non-root at container or pod level
_container_runs_non_root(container, _) if {
	container.securityContext.runAsNonRoot == true
}

_container_runs_non_root(container, _) if {
	container.securityContext.runAsUser > 0
}

_container_runs_non_root(_, pod_spec) if {
	pod_spec.securityContext.runAsNonRoot == true
}

_container_runs_non_root(_, pod_spec) if {
	pod_spec.securityContext.runAsUser > 0
}

# Get run-as-non-root status for evidence
_get_run_as_non_root(container) := "true" if {
	container.securityContext.runAsNonRoot == true
}

_get_run_as_non_root(container) := "false" if {
	container.securityContext.runAsNonRoot == false
}

_get_run_as_non_root(container) := "not set" if {
	not helpers.has_key(object.get(container, "securityContext", {}), "runAsNonRoot")
}

_get_run_as_user(container) := sprintf("%d", [container.securityContext.runAsUser]) if {
	helpers.has_key(object.get(container, "securityContext", {}), "runAsUser")
}

_get_run_as_user(container) := "not set" if {
	not helpers.has_key(object.get(container, "securityContext", {}), "runAsUser")
}

# Valid seccomp profiles for restricted PSS
_valid_seccomp_types := {"RuntimeDefault", "Localhost"}

_has_valid_seccomp(container, _) if {
	container.securityContext.seccompProfile.type in _valid_seccomp_types
}

_has_valid_seccomp(_, pod_spec) if {
	pod_spec.securityContext.seccompProfile.type in _valid_seccomp_types
}

_get_seccomp_type(container, _) := container.securityContext.seccompProfile.type if {
	helpers.has_key(object.get(object.get(container, "securityContext", {}), "seccompProfile", {}), "type")
}

_get_seccomp_type(_, pod_spec) := pod_spec.securityContext.seccompProfile.type if {
	helpers.has_key(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type")
}

_get_seccomp_type(container, pod_spec) := "not set" if {
	not helpers.has_key(object.get(object.get(container, "securityContext", {}), "seccompProfile", {}), "type")
	not helpers.has_key(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type")
}

# Must explicitly set allowPrivilegeEscalation to false
_explicitly_denies_privilege_escalation(container) if {
	container.securityContext.allowPrivilegeEscalation == false
}
