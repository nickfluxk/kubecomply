# METADATA
# title: Kubernetes Security Helpers
# description: Kubernetes-specific helper functions for security analysis.
# authors:
#   - KubeComply
# scope: subpackages
package lib.kubernetes

import rego.v1

# Dangerous capabilities that should be flagged.
dangerous_capabilities := {
	"NET_RAW",
	"SYS_ADMIN",
	"SYS_PTRACE",
	"SYS_MODULE",
	"DAC_OVERRIDE",
	"FOWNER",
	"SETUID",
	"SETGID",
	"NET_BIND_SERVICE",
	"SYS_CHROOT",
	"KILL",
	"AUDIT_WRITE",
}

# Highly dangerous capabilities that are almost never needed.
critical_capabilities := {
	"SYS_ADMIN",
	"NET_RAW",
	"SYS_PTRACE",
	"SYS_MODULE",
}

# is_privileged returns true if a container runs in privileged mode.
is_privileged(container) if {
	container.securityContext.privileged == true
}

# has_host_network returns true if the pod spec enables host networking.
has_host_network(pod_spec) if {
	pod_spec.hostNetwork == true
}

# has_host_pid returns true if the pod spec shares the host PID namespace.
has_host_pid(pod_spec) if {
	pod_spec.hostPID == true
}

# has_host_ipc returns true if the pod spec shares the host IPC namespace.
has_host_ipc(pod_spec) if {
	pod_spec.hostIPC == true
}

# runs_as_root returns true if the container is configured to run as root (UID 0)
# or does not explicitly set a non-root user.
runs_as_root(container) if {
	container.securityContext.runAsUser == 0
}

runs_as_root(container) if {
	not has_run_as_non_root(container)
	not has_run_as_user(container)
}

# has_run_as_non_root checks if the container has runAsNonRoot set to true.
has_run_as_non_root(container) if {
	container.securityContext.runAsNonRoot == true
}

# has_run_as_user checks if the container has runAsUser set to a non-zero value.
has_run_as_user(container) if {
	container.securityContext.runAsUser > 0
}

# has_dangerous_capabilities returns true if the container has any dangerous capabilities added.
has_dangerous_capabilities(container) if {
	cap := container.securityContext.capabilities.add[_]
	upper(cap) in dangerous_capabilities
}

# get_dangerous_caps returns the set of dangerous capabilities added to a container.
get_dangerous_caps(container) := {cap |
	cap := container.securityContext.capabilities.add[_]
	upper(cap) in dangerous_capabilities
}

# get_critical_caps returns the set of critical capabilities added to a container.
get_critical_caps(container) := {cap |
	cap := container.securityContext.capabilities.add[_]
	upper(cap) in critical_capabilities
}

# has_capability returns true if a container has a specific capability added.
has_capability(container, cap) if {
	added := container.securityContext.capabilities.add[_]
	upper(added) == upper(cap)
}

# drops_all_capabilities returns true if the container drops ALL capabilities.
drops_all_capabilities(container) if {
	dropped := container.securityContext.capabilities.drop[_]
	upper(dropped) == "ALL"
}

# allows_privilege_escalation returns true if privilege escalation is allowed.
allows_privilege_escalation(container) if {
	container.securityContext.allowPrivilegeEscalation == true
}

# allowPrivilegeEscalation defaults to true if not explicitly set to false.
allows_privilege_escalation(container) if {
	not container.securityContext.allowPrivilegeEscalation == false
	not has_field(container, "securityContext")
}

allows_privilege_escalation(container) if {
	not has_field(object.get(container, "securityContext", {}), "allowPrivilegeEscalation")
}

# has_read_only_root_fs returns true if the container has readOnlyRootFilesystem.
has_read_only_root_fs(container) if {
	container.securityContext.readOnlyRootFilesystem == true
}

# has_seccomp_profile returns true if the container or pod has a seccomp profile set.
has_seccomp_profile(container) if {
	container.securityContext.seccompProfile.type
}

# has_apparmor_profile returns true if the container has AppArmor annotation.
has_apparmor_profile(metadata, container_name) if {
	annotation_key := sprintf("container.apparmor.security.beta.kubernetes.io/%s", [container_name])
	metadata.annotations[annotation_key]
}

# is_cluster_admin returns true if a ClusterRole has full admin privileges.
is_cluster_admin(cluster_role) if {
	rule := cluster_role.rules[_]
	rule.apiGroups[_] == "*"
	rule.resources[_] == "*"
	rule.verbs[_] == "*"
}

# has_hostpath_volume returns true if the pod spec has hostPath volumes.
has_hostpath_volume(pod_spec) if {
	volume := pod_spec.volumes[_]
	volume.hostPath
}

# get_hostpath_volumes returns the set of hostPath volumes in the pod spec.
get_hostpath_volumes(pod_spec) := {volume.name |
	volume := pod_spec.volumes[_]
	volume.hostPath
}

# has_field checks whether an object has a specific field.
has_field(obj, field) if {
	_ = obj[field]
}

# is_default_service_account returns true if the service account is "default".
is_default_service_account(pod_spec) if {
	pod_spec.serviceAccountName == "default"
}

is_default_service_account(pod_spec) if {
	not has_field(pod_spec, "serviceAccountName")
}

# has_automount_sa_token returns true if automountServiceAccountToken is set to true
# or is not explicitly disabled.
has_automount_sa_token(pod_spec) if {
	pod_spec.automountServiceAccountToken == true
}

has_automount_sa_token(pod_spec) if {
	not has_field(pod_spec, "automountServiceAccountToken")
}

# has_secret_env_var returns true if a container uses secrets via environment variables.
has_secret_env_var(container) if {
	env := container.env[_]
	env.valueFrom.secretKeyRef
}

# has_secret_env_from returns true if a container uses secretRef in envFrom.
has_secret_env_from(container) if {
	envFrom := container.envFrom[_]
	envFrom.secretRef
}
