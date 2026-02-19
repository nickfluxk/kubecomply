# METADATA
# title: CIS Kubernetes Benchmark - Section 5.4 Secrets Management
# description: >
#   CIS Kubernetes Benchmark v1.8 Section 5.4 checks for
#   Secrets management best practices.
# authors:
#   - KubeComply
# custom:
#   benchmark: CIS Kubernetes Benchmark v1.8
#   section: "5.4"
package cis.policies.secrets

import rego.v1

import data.lib.helpers
import data.lib.kubernetes

# ============================================================
# KC-CIS-5.4.1: Prefer using Secrets as files over environment variables
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-CIS-5.4.1",
	"Prefer using Secrets as files over environment variables",
	sprintf("Container '%s' in %s '%s' exposes secrets via environment variables", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	"medium",
	concat("\n", [
		"Mount secrets as files instead of environment variables:",
		"",
		"spec:",
		"  containers:",
		sprintf("  - name: %s", [container.name]),
		"    # REMOVE env-based secret references:",
		"    # env:",
		"    # - name: SECRET_VAR",
		"    #   valueFrom:",
		"    #     secretKeyRef: ...",
		"    #",
		"    # USE volume-mounted secrets instead:",
		"    volumeMounts:",
		"    - name: secret-volume",
		"      mountPath: /etc/secrets",
		"      readOnly: true",
		"  volumes:",
		"  - name: secret-volume",
		"    secret:",
		"      secretName: my-secret",
		"      defaultMode: 0400  # Read-only for owner",
	]),
	workload,
	{
		"container_name": container.name,
		"secret_env_vars": concat(", ", _secret_env_var_names(container)),
	},
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	_container_has_secret_env(container)
}

results contains helpers.result_pass(
	"KC-CIS-5.4.1",
	"Prefer using Secrets as files over environment variables",
	sprintf("Container '%s' in %s '%s' does not expose secrets via env vars", [
		container.name,
		workload.kind,
		workload.metadata.name,
	]),
	workload,
) if {
	workload := _all_workloads[_]
	pod_spec := helpers.pod_spec_from_workload(workload)
	container := helpers.all_containers(pod_spec)[_]
	not _container_has_secret_env(container)
}

# ============================================================
# KC-CIS-5.4.2: Consider external secret storage
# ============================================================

# Warn if no external-secrets operator resources are found
results contains helpers.result_warn_with_evidence(
	"KC-CIS-5.4.2",
	"Consider external secret storage",
	"No external secret management solution detected (e.g., external-secrets, sealed-secrets, vault-agent)",
	"low",
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
	{"external_secrets_detected": "false"},
) if {
	not _has_external_secrets_operator
}

results contains helpers.result_pass(
	"KC-CIS-5.4.2",
	"Consider external secret storage",
	"External secret management solution detected in cluster",
	{"kind": "Cluster", "metadata": {"name": "cluster"}},
) if {
	_has_external_secrets_operator
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

_container_has_secret_env(container) if {
	kubernetes.has_secret_env_var(container)
}

_container_has_secret_env(container) if {
	kubernetes.has_secret_env_from(container)
}

_secret_env_var_names(container) := {name |
	env := container.env[_]
	env.valueFrom.secretKeyRef
	name := env.name
}

# Detect external-secrets operator by looking for relevant deployments
_has_external_secrets_operator if {
	deploy := input.deployments[_]
	contains(deploy.metadata.name, "external-secrets")
}

_has_external_secrets_operator if {
	deploy := input.deployments[_]
	contains(deploy.metadata.name, "sealed-secrets")
}

_has_external_secrets_operator if {
	deploy := input.deployments[_]
	contains(deploy.metadata.name, "vault")
}
