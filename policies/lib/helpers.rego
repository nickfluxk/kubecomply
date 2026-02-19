# METADATA
# title: KubeComply Helper Functions
# description: Common helper functions used across all KubeComply policies.
# authors:
#   - KubeComply
# scope: subpackages
package lib.helpers

import rego.v1

# result_pass produces a passing result object for a check.
result_pass(check_id, title, desc, resource) := {
	"check_id": check_id,
	"title": title,
	"description": desc,
	"severity": "info",
	"status": "pass",
	"remediation": "",
	"resource_kind": object.get(resource, "kind", ""),
	"resource_name": object.get(object.get(resource, "metadata", {}), "name", ""),
	"namespace": object.get(object.get(resource, "metadata", {}), "namespace", ""),
	"evidence_data": {},
}

# result_fail produces a failing result object for a check.
result_fail(check_id, title, desc, severity, remediation, resource) := {
	"check_id": check_id,
	"title": title,
	"description": desc,
	"severity": severity,
	"status": "fail",
	"remediation": remediation,
	"resource_kind": object.get(resource, "kind", ""),
	"resource_name": object.get(object.get(resource, "metadata", {}), "name", ""),
	"namespace": object.get(object.get(resource, "metadata", {}), "namespace", ""),
	"evidence_data": {},
}

# result_fail_with_evidence produces a failing result with evidence data.
result_fail_with_evidence(check_id, title, desc, severity, remediation, resource, evidence) := object.union(
	result_fail(check_id, title, desc, severity, remediation, resource),
	{"evidence_data": evidence},
)

# result_warn produces a warning result object for a check.
result_warn(check_id, title, desc, severity, resource) := {
	"check_id": check_id,
	"title": title,
	"description": desc,
	"severity": severity,
	"status": "warn",
	"remediation": "",
	"resource_kind": object.get(resource, "kind", ""),
	"resource_name": object.get(object.get(resource, "metadata", {}), "name", ""),
	"namespace": object.get(object.get(resource, "metadata", {}), "namespace", ""),
	"evidence_data": {},
}

# result_warn_with_evidence produces a warning result with evidence data.
result_warn_with_evidence(check_id, title, desc, severity, resource, evidence) := object.union(
	result_warn(check_id, title, desc, severity, resource),
	{"evidence_data": evidence},
)

# result_warn_with_evidence (7-arity) includes remediation guidance.
result_warn_with_evidence(check_id, title, desc, severity, remediation, resource, evidence) := object.union(
	result_warn(check_id, title, desc, severity, resource),
	{"remediation": remediation, "evidence_data": evidence},
)

# has_key checks if an object contains a given key.
has_key(obj, key) if {
	_ = obj[key]
}

# array_contains checks if an array contains a given value.
array_contains(arr, val) if {
	arr[_] == val
}

# resource_name extracts the name from a Kubernetes resource metadata.
resource_name(resource) := object.get(object.get(resource, "metadata", {}), "name", "<unknown>")

# resource_namespace extracts the namespace from a Kubernetes resource metadata.
resource_namespace(resource) := object.get(object.get(resource, "metadata", {}), "namespace", "")

# resource_ref builds a "Kind/namespace/name" reference string.
resource_ref(resource) := sprintf("%s/%s/%s", [
	object.get(resource, "kind", "Unknown"),
	resource_namespace(resource),
	resource_name(resource),
]) if {
	resource_namespace(resource) != ""
}

resource_ref(resource) := sprintf("%s/%s", [
	object.get(resource, "kind", "Unknown"),
	resource_name(resource),
]) if {
	resource_namespace(resource) == ""
}

# all_containers returns all containers (init + regular + ephemeral) from a pod spec.
all_containers(pod_spec) := array.concat(
	array.concat(
		object.get(pod_spec, "containers", []),
		object.get(pod_spec, "initContainers", []),
	),
	object.get(pod_spec, "ephemeralContainers", []),
)

# pod_spec_from_workload extracts the pod spec from a workload resource
# (Deployment, DaemonSet, StatefulSet, Job, etc.).
pod_spec_from_workload(resource) := resource.spec.template.spec if {
	resource.kind in {"Deployment", "DaemonSet", "StatefulSet", "Job", "ReplicaSet"}
}

pod_spec_from_workload(resource) := resource.spec if {
	resource.kind == "Pod"
}

pod_spec_from_workload(resource) := resource.spec.jobTemplate.spec.template.spec if {
	resource.kind == "CronJob"
}
