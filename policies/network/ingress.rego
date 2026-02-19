# METADATA
# title: Ingress and Service Exposure Analysis
# description: >
#   Analyzes service exposure through LoadBalancer and NodePort types,
#   and identifies services exposed without matching NetworkPolicy
#   protection.
# authors:
#   - KubeComply
# custom:
#   category: network
package network.ingress

import rego.v1

import data.lib.helpers

# ============================================================
# KC-NET-010: Inventory all LoadBalancer services
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-NET-010",
	"Inventory all LoadBalancer services",
	sprintf("Service '%s/%s' is exposed as LoadBalancer (external IPs: %s)", [
		object.get(svc.metadata, "namespace", "default"),
		svc.metadata.name,
		_get_lb_ips(svc),
	]),
	"medium",
	svc,
	{
		"service_name": svc.metadata.name,
		"namespace": object.get(svc.metadata, "namespace", "default"),
		"service_type": "LoadBalancer",
		"ports": _format_service_ports(svc),
		"external_ips": _get_lb_ips(svc),
	},
) if {
	svc := input.services[_]
	svc.spec.type == "LoadBalancer"
}

# Pass when no LoadBalancer services exist
results contains helpers.result_pass(
	"KC-NET-010",
	"Inventory all LoadBalancer services",
	"No LoadBalancer services found",
	{"kind": "Service", "metadata": {"name": "cluster-wide"}},
) if {
	count(_lb_services) == 0
}

_lb_services contains svc if {
	svc := input.services[_]
	svc.spec.type == "LoadBalancer"
}

# ============================================================
# KC-NET-011: Inventory all NodePort services
# ============================================================

results contains helpers.result_warn_with_evidence(
	"KC-NET-011",
	"Inventory all NodePort services",
	sprintf("Service '%s/%s' is exposed as NodePort", [
		object.get(svc.metadata, "namespace", "default"),
		svc.metadata.name,
	]),
	"medium",
	svc,
	{
		"service_name": svc.metadata.name,
		"namespace": object.get(svc.metadata, "namespace", "default"),
		"service_type": "NodePort",
		"ports": _format_service_ports(svc),
		"node_ports": _format_node_ports(svc),
	},
) if {
	svc := input.services[_]
	svc.spec.type == "NodePort"
}

results contains helpers.result_pass(
	"KC-NET-011",
	"Inventory all NodePort services",
	"No NodePort services found",
	{"kind": "Service", "metadata": {"name": "cluster-wide"}},
) if {
	count(_nodeport_services) == 0
}

_nodeport_services contains svc if {
	svc := input.services[_]
	svc.spec.type == "NodePort"
}

# ============================================================
# KC-NET-012: Services exposed without matching NetworkPolicy
# ============================================================

results contains helpers.result_fail_with_evidence(
	"KC-NET-012",
	"Services exposed without matching NetworkPolicy",
	sprintf("Service '%s/%s' (%s) has no NetworkPolicy protecting its namespace", [
		ns,
		svc.metadata.name,
		svc.spec.type,
	]),
	"high",
	concat("\n", [
		sprintf("Create a NetworkPolicy to control traffic to service '%s':", [svc.metadata.name]),
		"",
		"apiVersion: networking.k8s.io/v1",
		"kind: NetworkPolicy",
		"metadata:",
		sprintf("  name: allow-%s-ingress", [svc.metadata.name]),
		sprintf("  namespace: %s", [ns]),
		"spec:",
		"  podSelector:",
		"    matchLabels:",
		sprintf("      app: %s  # Match your service's pod selector", [svc.metadata.name]),
		"  policyTypes:",
		"  - Ingress",
		"  ingress:",
		"  - ports:",
		_format_netpol_ports(svc),
		"    from:",
		"    - namespaceSelector:",
		"        matchLabels:",
		"          purpose: ingress  # Restrict source namespaces",
	]),
	svc,
	{
		"service_name": svc.metadata.name,
		"namespace": ns,
		"service_type": svc.spec.type,
		"has_network_policy": "false",
	},
) if {
	svc := input.services[_]
	svc.spec.type in {"LoadBalancer", "NodePort"}
	ns := object.get(svc.metadata, "namespace", "default")
	not _namespace_has_netpol(ns)
}

results contains helpers.result_pass(
	"KC-NET-012",
	"Services exposed without matching NetworkPolicy",
	sprintf("Service '%s/%s' (%s) has NetworkPolicy in its namespace", [
		object.get(svc.metadata, "namespace", "default"),
		svc.metadata.name,
		svc.spec.type,
	]),
	svc,
) if {
	svc := input.services[_]
	svc.spec.type in {"LoadBalancer", "NodePort"}
	ns := object.get(svc.metadata, "namespace", "default")
	_namespace_has_netpol(ns)
}

# Pass when no externally exposed services exist
results contains helpers.result_pass(
	"KC-NET-012",
	"Services exposed without matching NetworkPolicy",
	"No externally exposed services (LoadBalancer/NodePort) found",
	{"kind": "Service", "metadata": {"name": "cluster-wide"}},
) if {
	count(_exposed_services) == 0
}

_exposed_services contains svc if {
	svc := input.services[_]
	svc.spec.type in {"LoadBalancer", "NodePort"}
}

# ============================================================
# Internal helpers
# ============================================================

_namespace_has_netpol(ns_name) if {
	np := input.network_policies[_]
	np.metadata.namespace == ns_name
}

_get_lb_ips(svc) := concat(", ", ips) if {
	ips := {ip |
		ingress := svc.status.loadBalancer.ingress[_]
		ip := object.get(ingress, "ip", object.get(ingress, "hostname", "pending"))
	}
	count(ips) > 0
}

_get_lb_ips(svc) := "pending" if {
	not helpers.has_key(object.get(object.get(svc, "status", {}), "loadBalancer", {}), "ingress")
}

_format_service_ports(svc) := concat(", ", {port_str |
	port := svc.spec.ports[_]
	port_str := sprintf("%d/%s", [port.port, object.get(port, "protocol", "TCP")])
})

_format_node_ports(svc) := concat(", ", {port_str |
	port := svc.spec.ports[_]
	helpers.has_key(port, "nodePort")
	port_str := sprintf("%d", [port.nodePort])
})

_format_netpol_ports(svc) := concat("\n", {port_str |
	port := svc.spec.ports[_]
	port_str := sprintf("    - port: %d\n      protocol: %s", [
		port.port,
		object.get(port, "protocol", "TCP"),
	])
})
