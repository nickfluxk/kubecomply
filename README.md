# KubeComply — Open-Source Kubernetes CIS Benchmark & Compliance Scanner

**Kubernetes compliance scanner** for CIS Benchmark v1.9, RBAC security analysis, Pod Security Standards, and NetworkPolicy coverage — with remediation YAML patches. Open-source alternative to kube-bench and Kubescape. Free forever.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/kubecomply/kubecomply)](https://goreportcard.com/report/github.com/kubecomply/kubecomply)
[![CIS Benchmark](https://img.shields.io/badge/CIS%20Benchmark-v1.9-green.svg)]()

## What is KubeComply?

KubeComply is a Kubernetes-native compliance scanner that runs CIS Benchmark v1.9, RBAC analysis, Pod Security Standards, and NetworkPolicy coverage checks against your cluster. It deploys as a Helm chart and provides actionable remediation guidance with exact YAML patches.

### Why KubeComply over kube-bench or Kubescape?

- **Full CIS v1.9** — ~150 checks with OPA/Rego policies you can read, modify, and extend
- **Deep RBAC analysis** — ClusterAdmin inventory, wildcard permissions, stale accounts, unused roles
- **NetworkPolicy coverage** — per-namespace coverage percentage, not just "do policies exist"
- **Remediation YAML** — every finding includes the exact YAML patch to fix it
- **Custom policies** — write your own Rego checks and plug them in
- **Tiny footprint** — read-only RBAC, <128Mi memory, <0.05% CPU idle

## Quick Start

### Install via Helm

```bash
helm repo add kubecomply https://kubecomply.github.io/charts
helm repo update
helm install kubecomply kubecomply/kubecomply
```

### Run a Scan via CLI

```bash
# Install CLI
brew install kubecomply/tap/kubecomply

# Run a full CIS benchmark scan
kubecomply scan --format table

# RBAC analysis
kubecomply analyze rbac

# NetworkPolicy coverage
kubecomply analyze network

# Export as JSON
kubecomply scan --format json -o results.json

# Export as HTML report
kubecomply scan --format html -o report.html
```

### Example Output

```
KubeComply — CIS Kubernetes Benchmark v1.9
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Compliance Score: 87.5% (82/94 checks passing)

CRITICAL  ██░░░░░░░░  2 findings
HIGH      ████░░░░░░  5 findings
MEDIUM    ███░░░░░░░  4 findings
LOW       █░░░░░░░░░  1 finding

┌─────────┬──────────────────────────────────────────┬──────────┬────────┐
│ Check   │ Title                                    │ Severity │ Status │
├─────────┼──────────────────────────────────────────┼──────────┼────────┤
│ CIS-5.1 │ ClusterAdmin role not bound to users     │ CRITICAL │ FAIL   │
│ CIS-5.2 │ Wildcard permissions in ClusterRoles     │ CRITICAL │ FAIL   │
│ CIS-5.3 │ NetworkPolicy defined for all namespaces │ HIGH     │ FAIL   │
│ CIS-1.1 │ API server anonymous auth disabled       │ HIGH     │ PASS   │
│ ...     │                                          │          │        │
└─────────┴──────────────────────────────────────────┴──────────┴────────┘
```

## Features

### Open Source (Free Forever)
- Full CIS Kubernetes Benchmark v1.9 (~150 checks)
- NSA/CISA Hardening Guide checks
- RBAC analyzer (ClusterAdmin, wildcards, stale accounts)
- Pod Security Standards enforcement checks
- NetworkPolicy coverage analysis
- OPA/Rego policy engine with custom policy support
- CLI: JSON, HTML, terminal table output
- Basic self-hosted web dashboard
- Prometheus metrics export
- Helm chart deployment (multi-arch: AMD64 + ARM64)
- Fully offline — no phone-home, no SaaS required

### Professional (Paid)

Need SOC 2 evidence packages? KubeComply Professional turns your scan results into auditor-ready evidence.

| Feature | OSS | Professional |
|---------|-----|-------------|
| CIS Benchmark v1.9 | Full | Full |
| RBAC Deep Analysis | Yes | Yes |
| Custom OPA Policies | Yes | Yes |
| SOC 2 CC Control Mapping | - | CC6-CC9 + A1 |
| Auditor-Ready PDF Evidence | - | Yes |
| Chain of Custody (SHA-256 + timestamps) | - | Yes |
| Auditor Collaboration Portal | - | Yes |
| Continuous Drift Monitoring | - | Yes |
| Weekly Executive Digest | - | Yes |
| Slack / PagerDuty Alerting | - | Yes |
| 2-Year Evidence History | - | Yes |

[Learn more about Professional →](https://kubecomply.io/professional)

## Architecture

```
┌──────────────────────────────────────────────────┐
│                 Your K8s Cluster                  │
│                                                   │
│  ┌─────────────────────────────────────────────┐ │
│  │          KubeComply Agent (OSS)              │ │
│  │  ┌──────────┐  ┌────────┐  ┌────────────┐  │ │
│  │  │ CIS Scan │  │ RBAC   │  │ Network    │  │ │
│  │  │ Engine   │  │Analyzer│  │ Analyzer   │  │ │
│  │  └────┬─────┘  └───┬────┘  └─────┬──────┘  │ │
│  │       └─────────────┼─────────────┘         │ │
│  │              ┌──────┴──────┐                 │ │
│  │              │ OPA/Rego    │                 │ │
│  │              │ Policy Eng. │                 │ │
│  │              └──────┬──────┘                 │ │
│  │                     │                        │ │
│  │         ┌───────────┴──────────┐             │ │
│  │         │ CLI / Dashboard /    │             │ │
│  │         │ JSON / HTML / Table  │             │ │
│  │         └──────────────────────┘             │ │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

## Documentation

- [**Complete Setup Guide**](docs/setup-guide.md) — Installation, configuration, development, deployment, and FAQ
- [Installation Guide](docs/installation.md)
- [Configuration Reference](docs/configuration.md)
- [Writing Custom OPA/Rego Policies](docs/custom-policies.md)
- [RBAC Analysis Guide](docs/rbac-analysis.md)
- [API Reference](docs/api-reference.md)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The easiest way to contribute is to add new Rego policies — see the existing policies in `policies/` for examples.

## Security

KubeComply uses **read-only** Kubernetes API access. See [SECURITY.md](SECURITY.md) for our security model and responsible disclosure policy.

## License

Apache 2.0 — see [LICENSE](LICENSE).
