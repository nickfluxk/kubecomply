# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in KubeComply, please report it responsibly.

**Email:** security@kubecomply.io

**Please include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

**Our commitment:**
- We will acknowledge receipt within 24 hours
- We will provide an initial assessment within 72 hours
- Critical vulnerabilities will be patched within 7 days
- We follow a 90-day responsible disclosure embargo

## Security Model

### Agent (OSS)

The KubeComply agent operates with **read-only** access to the Kubernetes API:

| API Group | Resources | Verbs | Purpose |
|-----------|-----------|-------|---------|
| core ("") | pods, services, namespaces, nodes, secrets* | get, list, watch | Workload scanning |
| rbac.authorization.k8s.io | roles, rolebindings, clusterroles, clusterrolebindings | get, list, watch | RBAC analysis |
| networking.k8s.io | networkpolicies, ingresses | get, list, watch | Network segmentation |
| apps | deployments, daemonsets, statefulsets | get, list, watch | Workload security context |
| admissionregistration.k8s.io | mutating/validatingwebhookconfigurations | get, list | Change control |
| policy | poddisruptionbudgets | get, list | Availability |

*\*Secrets: metadata only (name, namespace, labels, annotations, mount type). The agent **never** reads Secret `.data` fields. This is enforced in code with a build-failing test.*

### SaaS Platform

- All data encrypted in transit (TLS 1.3) and at rest (AES-256)
- Per-tenant data isolation via row-level security
- Evidence records are append-only (immutable once written)
- Application audit logs retained for 7 years
- SBOM published for every release

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
