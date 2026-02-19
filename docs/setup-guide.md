# KubeComply Setup Guide — Kubernetes CIS Benchmark Compliance Scanner Installation & Configuration

> **Version:** 0.1.0 | **License:** Apache 2.0 | **Updated:** 2026-02-19

KubeComply is an open-source Kubernetes compliance scanner that runs **CIS Benchmark v1.9** (~150 checks), **RBAC security analysis**, **Pod Security Standards** validation, and **NetworkPolicy coverage** analysis against your cluster. This guide covers everything you need to install, configure, develop, test, and deploy KubeComply — whether you're setting up the CLI on your laptop, deploying the Helm chart to a production cluster, or contributing to the codebase. If you're looking for an alternative to kube-bench or Kubescape with deeper RBAC analysis, remediation YAML patches, and custom OPA/Rego policy support, start here.

---

## Table of Contents

1. [What is KubeComply — Kubernetes Compliance Scanner Overview](#1-what-is-kubecomply--kubernetes-compliance-scanner-overview)
2. [Architecture — How KubeComply Scans Your Cluster](#2-architecture--how-kubecomply-scans-your-cluster)
3. [Prerequisites — System Requirements for Installation](#3-prerequisites--system-requirements-for-installation)
4. [Repository Structure](#4-repository-structure)
5. [Quick Start — Install KubeComply in 5 Minutes](#5-quick-start--install-kubecomply-in-5-minutes)
6. [Go Agent & CLI Setup — Building the Kubernetes Scanner](#6-go-agent--cli-setup--building-the-kubernetes-scanner)
7. [OPA/Rego Policy Development — Writing Custom Compliance Rules](#7-oparego-policy-development--writing-custom-compliance-rules)
8. [Python Platform Setup — FastAPI SaaS Backend](#8-python-platform-setup--fastapi-saas-backend)
9. [React Frontend Setup — Compliance Dashboard UI](#9-react-frontend-setup--compliance-dashboard-ui)
10. [Docker Compose — Run Full Stack Locally](#10-docker-compose--run-full-stack-locally)
11. [Kubernetes Deployment with Helm Chart](#11-kubernetes-deployment-with-helm-chart)
12. [Custom Resource Definitions — ComplianceScan & CompliancePolicy CRDs](#12-custom-resource-definitions--compliancescan--compliancepolicy-crds)
13. [Configuration Reference — Environment Variables & Settings](#13-configuration-reference--environment-variables--settings)
14. [Database Migrations with Alembic (PostgreSQL)](#14-database-migrations-with-alembic-postgresql)
15. [Background Workers — Celery Task Queue Setup](#15-background-workers--celery-task-queue-setup)
16. [Running Tests — Go, OPA, Python, and Frontend](#16-running-tests--go-opa-python-and-frontend)
17. [Linting & Code Quality](#17-linting--code-quality)
18. [Production Deployment — Kubernetes & Docker Compose](#18-production-deployment--kubernetes--docker-compose)
19. [Security Model — Read-Only RBAC & Pod Security](#19-security-model--read-only-rbac--pod-security)
20. [Troubleshooting — Common Issues & Fixes](#20-troubleshooting--common-issues--fixes)
21. [FAQ — Frequently Asked Questions](#21-faq--frequently-asked-questions)

---

## 1. What is KubeComply — Kubernetes Compliance Scanner Overview

KubeComply is a **Kubernetes-native compliance scanner** with an open-core architecture:

| Tier | What It Does | License |
|------|-------------|---------|
| **OSS (Open Source)** | CIS Benchmark v1.9 (~150 checks), RBAC analysis, Pod Security Standards, NetworkPolicy coverage, OPA/Rego policy engine, CLI/Dashboard, Prometheus metrics | Apache 2.0 |
| **Professional (Paid)** | SOC 2 CC control mapping, auditor-ready PDF evidence, chain of custody, drift monitoring, auditor collaboration portal, alerting, executive digest | Commercial |

The OSS agent runs **inside your cluster** with read-only access. The Professional tier adds a SaaS platform (FastAPI + React + Celery) for evidence management and auditor workflows.

---

## 2. Architecture — How KubeComply Scans Your Cluster

```
┌────────────────────────────────────────────────────────────────────┐
│                        Your Kubernetes Cluster                      │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                   KubeComply Agent (OSS - Go)                 │  │
│  │                                                               │  │
│  │  ┌────────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │  │
│  │  │ CIS Scan   │  │  RBAC    │  │ Network  │  │    PSS    │  │  │
│  │  │ Engine     │  │ Analyzer │  │ Analyzer │  │  Checker  │  │  │
│  │  └─────┬──────┘  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │  │
│  │        └───────────────┼─────────────┼──────────────┘        │  │
│  │                   ┌────┴─────────────┴────┐                  │  │
│  │                   │   OPA/Rego Policy Eng  │                  │  │
│  │                   └───────────┬────────────┘                  │  │
│  │                        ┌──────┴──────┐                        │  │
│  │                        │  Reporter   │                        │  │
│  │                        │ JSON/HTML/  │                        │  │
│  │                        │   Table     │                        │  │
│  │                        └─────────────┘                        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                               │ (optional)                          │
│                               ▼                                     │
│               ┌───────────────────────────────┐                     │
│               │   SaaS Platform (Professional) │                    │
│               │  FastAPI + Celery + React      │                    │
│               └───────────────────────────────┘                     │
└────────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Language | Location | Purpose |
|-----------|----------|----------|---------|
| **Agent** | Go 1.22 | `agent/` | Kubernetes operator — reconciles `ComplianceScan` CRDs |
| **CLI** | Go 1.22 | `agent/cmd/cli/` | CLI tool for ad-hoc scans (`kubecomply scan`) |
| **Policies** | Rego (OPA) | `policies/` | CIS, PSS, RBAC, Network compliance rules |
| **API** | Python 3.12 (FastAPI) | `platform/api/` | REST API for the SaaS platform |
| **Workers** | Python 3.12 (Celery) | `platform/workers/` | Background task processing (evidence generation, drift, alerts) |
| **Evidence Engine** | Python 3.12 | `platform/evidence_engine/` | SOC 2 evidence PDF generation |
| **Frontend** | TypeScript (React 18) | `platform/frontend/` | SaaS dashboard UI |
| **Helm Chart** | YAML | `charts/kubecomply/` | Kubernetes deployment packaging |
| **Docker** | Dockerfiles | `deploy/` | Container images and compose configs |

---

## 3. Prerequisites — System Requirements for Installation

### Required for All Development

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **Git** | 2.39+ | `brew install git` | Source control |
| **Docker** | 24.0+ | `brew install --cask docker` | Containers |
| **Docker Compose** | v2.20+ | Included with Docker Desktop | Multi-container orchestration |

### For Go Agent / CLI Development

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **Go** | 1.22.0 | `brew install go` | Agent and CLI compilation |
| **golangci-lint** | 1.55+ | `brew install golangci-lint` | Go linting |
| **controller-gen** | 0.15+ | `go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest` | CRD/deepcopy generation |

### For OPA Policy Development

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **OPA** | 1.0+ | `brew install opa` | Rego policy testing |

### For Python Platform Development

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **Python** | 3.11+ (3.12 recommended) | `brew install python@3.12` | API and workers |
| **pip** | 23.0+ | Included with Python | Package management |
| **PostgreSQL client libs** | 16+ | `brew install libpq` | `asyncpg` driver |
| **Cairo/Pango** | — | `brew install cairo pango gdk-pixbuf libffi` | WeasyPrint PDF rendering |

### For Frontend Development

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **Node.js** | 20.0+ | `brew install node@20` | Frontend runtime |
| **npm** | 10.0+ | Included with Node.js | Package management |

### For Kubernetes Deployment

| Tool | Minimum Version | Install Command (macOS) | Purpose |
|------|----------------|------------------------|---------|
| **kubectl** | 1.28+ | `brew install kubectl` | Cluster management |
| **Helm** | 3.12+ | `brew install helm` | Chart deployment |
| **kind** / **minikube** | Latest | `brew install kind` | Local K8s cluster (optional) |

### Linux (Debian/Ubuntu) Prerequisites

```bash
# System packages
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    libpq-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    libcairo2 \
    ca-certificates \
    curl \
    git

# Go (download from https://go.dev/dl/)
wget https://go.dev/dl/go1.22.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.10.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Node.js 20 (via NodeSource)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Python 3.12
sudo apt-get install -y python3.12 python3.12-venv python3-pip

# OPA
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64_static
chmod +x opa && sudo mv opa /usr/local/bin/

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

---

## 4. Repository Structure

```
kubecomply/
├── agent/                          # Go agent + CLI
│   ├── api/v1alpha1/               #   CRD types (ComplianceScan, CompliancePolicy)
│   │   ├── types.go                #     Spec, Status, FindingSummary structs
│   │   ├── groupversion_info.go    #     GVK registration
│   │   └── zz_generated.deepcopy.go #    Auto-generated deep copy methods
│   ├── cmd/
│   │   ├── agent/main.go           #   Operator entrypoint (controller-runtime)
│   │   └── cli/                    #   CLI entrypoint
│   │       ├── main.go             #     Root + analyze + report commands
│   │       ├── scan.go             #     `kubecomply scan` command
│   │       └── version.go          #     `kubecomply version` command
│   ├── internal/
│   │   ├── controller/             #   ComplianceScan reconciler
│   │   └── dashboard/              #   Embedded web dashboard
│   │       ├── dashboard.go        #     HTTP handler + JSON API
│   │       └── static/index.html   #     Single-page dashboard UI
│   ├── pkg/
│   │   ├── k8s/client.go           #   Read-only K8s client wrapper
│   │   ├── metrics/metrics.go      #   Prometheus metrics
│   │   ├── network/analyzer.go     #   NetworkPolicy coverage analyzer
│   │   ├── policies/               #   OPA policy engine wrapper
│   │   │   ├── engine.go           #     Policy loading and evaluation
│   │   │   └── result.go           #     Check result types
│   │   ├── pss/checker.go          #   Pod Security Standards checker
│   │   ├── rbac/analyzer.go        #   RBAC security analyzer
│   │   ├── report/                 #   Report generators
│   │   │   ├── html.go             #     HTML report
│   │   │   ├── json.go             #     JSON report
│   │   │   ├── table.go            #     Terminal table report
│   │   │   └── types.go            #     Reporter interface
│   │   ├── saas/client.go          #   SaaS API client (upload results)
│   │   └── scanner/                #   Core scan orchestrator
│   │       ├── scanner.go          #     Scanner, Analyzer, PolicyEvaluator interfaces
│   │       └── types.go            #     Finding, ScanResult, ScanConfig, Severity
│   ├── Dockerfile                  #   Multi-stage agent image
│   ├── Makefile                    #   Agent build targets
│   └── go.mod                      #   Go module definition
│
├── policies/                       # OPA/Rego policy library
│   ├── lib/
│   │   ├── helpers.rego            #   Result builder helpers
│   │   └── kubernetes.rego         #   K8s security helper functions
│   ├── cis/                        #   CIS Kubernetes Benchmark v1.9
│   │   ├── control_plane/          #     API server, controller manager, scheduler
│   │   ├── etcd/                   #     etcd security checks
│   │   ├── policies/               #     General, network, PSS, RBAC, secrets
│   │   └── worker_nodes/           #     Kubelet configuration checks
│   ├── pss/                        #   Pod Security Standards
│   │   ├── baseline.rego           #     Baseline profile (6 checks)
│   │   └── restricted.rego         #     Restricted profile
│   ├── rbac/                       #   RBAC security checks
│   │   ├── cluster_admin.rego      #     ClusterAdmin binding detection
│   │   ├── stale_accounts.rego     #     Unused service accounts
│   │   └── wildcards.rego          #     Wildcard permission detection
│   └── network/                    #   Network security checks
│       ├── coverage.rego           #     NetworkPolicy coverage analysis
│       └── ingress.rego            #     Ingress security checks
│
├── platform/                       # SaaS Platform (Professional)
│   ├── api/                        #   FastAPI application
│   │   ├── main.py                 #     App factory (lifespan, middleware, routers)
│   │   ├── config.py               #     Settings (env vars / .env file)
│   │   ├── dependencies.py         #     FastAPI dependency injection
│   │   ├── auth/                   #     JWT authentication
│   │   │   ├── router.py           #       /login, /register, /refresh endpoints
│   │   │   ├── jwt.py              #       Token creation/validation
│   │   │   ├── permissions.py      #       RBAC permission decorators
│   │   │   ├── schemas.py          #       Pydantic request/response models
│   │   │   └── service.py          #       User auth business logic
│   │   ├── auditor/                #     Auditor collaboration endpoints
│   │   ├── clusters/               #     Cluster management endpoints
│   │   ├── drift/                  #     Compliance drift endpoints
│   │   ├── evidence/               #     Evidence package endpoints
│   │   ├── license/                #     License management endpoints
│   │   ├── organizations/          #     Multi-tenant org management
│   │   ├── scans/                  #     Scan result ingestion + queries
│   │   │   └── ingest.py           #       Agent scan result receiver
│   │   ├── users/                  #     User management endpoints
│   │   ├── webhooks/               #     Webhook management endpoints
│   │   ├── common/                 #     Shared utilities
│   │   │   ├── exceptions.py       #       Custom exception classes
│   │   │   ├── hashing.py          #       Password hashing (bcrypt)
│   │   │   ├── pagination.py       #       Cursor/offset pagination
│   │   │   ├── responses.py        #       Standardized API responses
│   │   │   └── s3.py               #       S3/MinIO client helper
│   │   ├── middleware/             #     HTTP middleware
│   │   │   ├── audit_log.py        #       Audit logging
│   │   │   ├── request_id.py       #       Request ID injection
│   │   │   └── tenant.py           #       Multi-tenant context extraction
│   │   └── tests/                  #     API tests
│   │
│   ├── db/                         #   Database layer
│   │   ├── base.py                 #     SQLAlchemy declarative base + TenantBase mixin
│   │   ├── session.py              #     Async engine + session factory (asyncpg)
│   │   ├── models/                 #     SQLAlchemy ORM models
│   │   │   ├── user.py             #       User model + roles
│   │   │   ├── organization.py     #       Organization (tenant)
│   │   │   ├── cluster.py          #       Registered clusters
│   │   │   ├── scan.py             #       Scan results
│   │   │   ├── evidence.py         #       Evidence packages
│   │   │   ├── cc_control.py       #       SOC 2 CC controls
│   │   │   ├── drift.py            #       Compliance drift records
│   │   │   ├── compliance_score.py #       Historical compliance scores
│   │   │   ├── auditor.py          #       Auditor reviews/comments
│   │   │   ├── alert.py            #       Alert configurations
│   │   │   ├── audit_log.py        #       Audit trail
│   │   │   └── license.py          #       License keys
│   │   └── migrations/             #     Alembic migration files
│   │       ├── env.py              #       Alembic environment (async-aware)
│   │       ├── script.py.mako      #       Migration template
│   │       └── versions/           #       Generated migration files
│   │
│   ├── evidence_engine/            #   SOC 2 evidence generation
│   │   ├── generator.py            #     Evidence package builder
│   │   ├── mapping_engine.py       #     Scan → CC control mapping
│   │   ├── narrative.py            #     Natural language narratives
│   │   ├── pdf_renderer.py         #     WeasyPrint PDF generation
│   │   ├── chain_of_custody.py     #     SHA-256 integrity verification
│   │   ├── s3_storage.py           #     S3/MinIO storage backend
│   │   ├── data/                   #     Static mapping data
│   │   │   ├── cc_controls.json    #       SOC 2 CC control definitions
│   │   │   ├── check_mappings.json #       Scan check → CC control map
│   │   │   └── narrative_templates.json #  Narrative text templates
│   │   ├── templates/              #     Jinja2 HTML templates for PDFs
│   │   └── styles/evidence.css     #     PDF stylesheet
│   │
│   ├── workers/                    #   Celery background tasks
│   │   ├── celery_app.py           #     Celery app factory + routing
│   │   ├── schedules.py            #     Celery Beat periodic schedules
│   │   └── tasks/
│   │       ├── evidence_generation.py #   PDF evidence generation
│   │       ├── drift_processing.py    #   Compliance drift detection
│   │       ├── alert_dispatch.py      #   Slack/PagerDuty/email alerts
│   │       ├── compliance_scoring.py  #   Daily score computation
│   │       └── executive_digest.py    #   Weekly executive summary
│   │
│   ├── frontend/                   #   React SPA
│   │   ├── package.json            #     Dependencies + scripts
│   │   ├── vite.config.ts          #     Vite build config (proxy → :8000)
│   │   ├── tsconfig.json           #     TypeScript config (strict)
│   │   ├── tailwind.config.ts      #     Tailwind CSS config
│   │   ├── postcss.config.js       #     PostCSS config
│   │   ├── index.html              #     HTML entry point
│   │   └── src/
│   │       ├── main.tsx            #       React entry
│   │       ├── App.tsx             #       Root component + routing
│   │       ├── globals.css         #       Global styles + CSS variables
│   │       ├── api/                #       API client layer (axios + react-query)
│   │       ├── components/         #       Reusable UI components
│   │       ├── contexts/           #       React contexts (Auth, Org)
│   │       ├── hooks/              #       Custom hooks (useScans, useClusters...)
│   │       ├── lib/                #       Utilities, constants, routes
│   │       ├── pages/              #       Page components (dashboard, scans, evidence...)
│   │       └── types/              #       TypeScript type definitions
│   │
│   ├── pyproject.toml              #   Python project config (hatchling build)
│   └── alembic.ini                 #   Alembic migration config
│
├── charts/kubecomply/              # Helm chart
│   ├── Chart.yaml                  #   Chart metadata (v0.1.0)
│   ├── values.yaml                 #   Default values
│   ├── crds/                       #   Custom Resource Definitions
│   │   ├── compliancescan.yaml     #     ComplianceScan CRD
│   │   └── compliancepolicy.yaml   #     CompliancePolicy CRD
│   └── templates/                  #   Kubernetes manifests
│       ├── _helpers.tpl            #     Template helpers
│       ├── deployment.yaml         #     Agent deployment
│       ├── service.yaml            #     Agent service
│       ├── serviceaccount.yaml     #     ServiceAccount
│       ├── clusterrole.yaml        #     Read-only ClusterRole
│       ├── clusterrolebinding.yaml #     ClusterRoleBinding
│       ├── configmap.yaml          #     Scanner configuration
│       └── servicemonitor.yaml     #     Prometheus ServiceMonitor (optional)
│
├── deploy/                         # Docker deployment files
│   ├── docker-compose.yml          #   Development compose (all services)
│   ├── docker-compose.prod.yml     #   Production compose overlay
│   ├── Dockerfile.api              #   Python API image
│   ├── Dockerfile.frontend         #   React frontend (dev + nginx prod)
│   ├── Dockerfile.worker           #   Celery worker image
│   └── nginx.conf                  #   Nginx config for frontend
│
├── examples/                       # Example configurations
│   ├── scan-full.yaml              #   ComplianceScan CR example
│   └── values-professional.yaml    #   Helm values for Professional tier
│
├── Makefile                        # Top-level build targets
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── LICENSE                         # Apache 2.0
└── .gitignore
```

---

## 5. Quick Start — Install KubeComply in 5 Minutes

The fastest path to running KubeComply locally with all services:

### Option A: Docker Compose (Recommended)

```bash
# Clone the repo
git clone https://github.com/nickfluxk/kubecomply.git
cd kubecomply

# Start everything (API, Worker, Frontend, PostgreSQL, Redis, MinIO)
make docker-up

# Verify services are running
docker compose -f deploy/docker-compose.yml ps
```

| Service | URL | Credentials |
|---------|-----|------------|
| **Frontend** | http://localhost:5173 | Register a new account |
| **API Docs** | http://localhost:8000/api/docs | — |
| **API Health** | http://localhost:8000/healthz | — |
| **MinIO Console** | http://localhost:9001 | `kubecomply` / `devdevdevdev` |
| **PostgreSQL** | `localhost:5432` | `kubecomply` / `devpassword` |
| **Redis** | `localhost:6379` | No auth |

### Option B: CLI Only (No Docker Required)

```bash
# Clone and build the CLI
git clone https://github.com/nickfluxk/kubecomply.git
cd kubecomply
make cli

# Run a scan (requires kubectl access to a cluster)
./agent/bin/kubecomply scan --format table

# RBAC analysis
./agent/bin/kubecomply analyze rbac

# NetworkPolicy coverage
./agent/bin/kubecomply analyze network

# Export results
./agent/bin/kubecomply scan --format json -o results.json
./agent/bin/kubecomply scan --format html -o report.html
```

### Option C: Helm Chart (Into a Kubernetes Cluster)

```bash
# From the cloned repo directory
helm install kubecomply charts/kubecomply

# Check status
kubectl get compliancescans -A
```

---

## 6. Go Agent & CLI Setup — Building the Kubernetes Scanner

### Build

```bash
# From repository root

# Build the operator agent (runs inside K8s)
make agent
# Output: agent/bin/kubecomply-agent

# Build the CLI (runs on your machine)
make cli
# Output: agent/bin/kubecomply

# Or build from the agent directory directly
cd agent
make build       # Agent
make build-cli   # CLI
```

### Build with Version Info

The build injects version, git commit, and build date via ldflags:

```bash
VERSION=0.2.0 make cli
./agent/bin/kubecomply version
# KubeComply CLI
#   Version:    0.2.0
#   Git Commit: abc1234
#   Build Date: 2026-02-19T00:00:00Z
#   Go Version: go1.22.x
#   Platform:   darwin/arm64
```

### Go Module Dependencies

Key dependencies in `agent/go.mod`:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `github.com/open-policy-agent/opa` | v1.1.0 | OPA/Rego policy engine |
| `github.com/prometheus/client_golang` | v1.20.0 | Prometheus metrics |
| `github.com/spf13/cobra` | v1.8.1 | CLI framework |
| `github.com/spf13/viper` | v1.19.0 | Configuration |
| `k8s.io/client-go` | v0.31.0 | Kubernetes client |
| `sigs.k8s.io/controller-runtime` | v0.19.0 | Operator framework |

### Download Dependencies

```bash
cd agent
go mod download
go mod verify
```

### CLI Commands Reference

```bash
# Full compliance scan (CIS + RBAC + Network + PSS)
kubecomply scan

# Specific scan type
kubecomply scan --scan-type cis
kubecomply scan --scan-type rbac
kubecomply scan --scan-type network
kubecomply scan --scan-type pss

# Filter by severity
kubecomply scan --severity-threshold high

# Target specific namespace
kubecomply scan --namespace production

# Custom kubeconfig
kubecomply scan --kubeconfig /path/to/kubeconfig

# Custom policy directory
kubecomply scan --policy-path ./my-policies

# Output formats
kubecomply scan --format table    # Terminal table (default)
kubecomply scan --format json     # JSON
kubecomply scan --format html     # HTML report

# Write to file
kubecomply scan --format json -o results.json
kubecomply scan --format html -o report.html

# Focused analysis
kubecomply analyze rbac
kubecomply analyze rbac --namespace kube-system
kubecomply analyze network

# Generate report from saved results
kubecomply report --input results.json --format html -o report.html

# Version info
kubecomply version
kubecomply version --json

# Verbose logging
kubecomply scan -v
```

### Agent (Operator) Flags

When running as a Kubernetes operator:

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-bind-address` | `:8080` | Prometheus metrics endpoint |
| `--health-probe-bind-address` | `:8081` | Health/readiness probes |
| `--leader-elect` | `false` | Enable leader election for HA |
| `--policy-dir` | `""` | Directory with custom Rego policies |
| `--saas-endpoint` | `""` | KubeComply SaaS API URL (empty = disabled) |

### CRD Code Generation

If you modify the CRD types in `agent/api/v1alpha1/types.go`:

```bash
cd agent

# Regenerate deepcopy methods and CRD manifests
make generate

# This runs:
#   controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
#   controller-gen crd paths="./..." output:crd:artifacts:config=../charts/kubecomply/crds
```

### Docker Image

```bash
# Build the agent Docker image
docker build -t kubecomply-agent:dev -f agent/Dockerfile agent/

# Build with version args
docker build \
  --build-arg VERSION=0.1.0 \
  --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
  --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") \
  -t kubecomply-agent:0.1.0 \
  -f agent/Dockerfile agent/
```

The agent Dockerfile uses a multi-stage build:
1. **Builder stage:** `golang:1.22-alpine` — compiles the binary
2. **Runtime stage:** `alpine:3.20` — minimal image with `ca-certificates` and a non-root user (UID 65534)

---

## 7. OPA/Rego Policy Development — Writing Custom Compliance Rules

### Policy Structure

All policies live under `policies/` and follow a consistent pattern:

```
policies/
├── lib/                    # Shared helper libraries
│   ├── helpers.rego        # Result builders (result_pass, result_fail, etc.)
│   └── kubernetes.rego     # K8s security helpers (is_privileged, runs_as_root, etc.)
├── cis/                    # CIS Kubernetes Benchmark v1.9
│   ├── control_plane/      # API server, controller manager, scheduler
│   ├── etcd/               # etcd security
│   ├── policies/           # Workload-level policies
│   └── worker_nodes/       # Kubelet configuration
├── pss/                    # Pod Security Standards
│   ├── baseline.rego       # Baseline profile
│   └── restricted.rego     # Restricted profile
├── rbac/                   # RBAC checks
│   ├── cluster_admin.rego  # ClusterAdmin binding detection
│   ├── stale_accounts.rego # Unused service accounts
│   └── wildcards.rego      # Wildcard permission detection
└── network/                # Network checks
    ├── coverage.rego       # NetworkPolicy coverage
    └── ingress.rego        # Ingress security
```

### Run Policy Tests

```bash
# Run all policy tests
make policy-test
# Equivalent: opa test policies/ -v

# Test a specific policy
opa test policies/pss/ -v

# Test with coverage
opa test policies/ -v --coverage
```

### Format Policies

```bash
make policy-fmt
# Equivalent: opa fmt -w policies/
```

### Writing Custom Policies

Every policy check must produce a result object with these fields:

| Field | Type | Description |
|-------|------|-------------|
| `check_id` | string | Unique ID (e.g., `KC-PSS-B-001`) |
| `title` | string | Human-readable title |
| `description` | string | What the check found |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `remediation` | string | YAML patch or instructions to fix |

Example custom policy:

```rego
# policies/custom/no-latest-tag.rego
package custom.no_latest_tag

import rego.v1
import data.lib.helpers

results contains helpers.result_fail(
    "KC-CUSTOM-001",
    "No :latest image tag",
    sprintf("Container '%s' in %s '%s' uses :latest tag", [
        container.name,
        workload.kind,
        workload.metadata.name,
    ]),
    "medium",
    "Pin to a specific image digest or version tag.",
    workload,
) if {
    workload := input.deployments[_]
    container := workload.spec.template.spec.containers[_]
    endswith(container.image, ":latest")
}
```

Write a corresponding test:

```rego
# policies/custom/no-latest-tag_test.rego
package custom.no_latest_tag_test

import rego.v1
import data.custom.no_latest_tag

test_latest_tag_fails if {
    count(no_latest_tag.results) > 0 with input as {
        "deployments": [{
            "kind": "Deployment",
            "metadata": {"name": "test", "namespace": "default"},
            "spec": {"template": {"spec": {"containers": [{
                "name": "app",
                "image": "nginx:latest",
            }]}}},
        }],
    }
}
```

### Using Custom Policies with the CLI

```bash
kubecomply scan --policy-path ./policies/custom
```

### Using Custom Policies with the Operator

Create a ConfigMap with your policy and reference it in a `CompliancePolicy` CR:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: custom-policies
  namespace: kubecomply
data:
  no-latest-tag.rego: |
    package custom.no_latest_tag
    # ... your policy here ...
---
apiVersion: compliance.kubecomply.io/v1alpha1
kind: CompliancePolicy
metadata:
  name: no-latest-tag
  namespace: kubecomply
spec:
  category: custom
  severity: medium
  regoPolicyConfigMapRef:
    name: custom-policies
    key: no-latest-tag.rego
  enabled: true
```

---

## 8. Python Platform Setup — FastAPI SaaS Backend

### Initial Setup

```bash
cd platform

# Create a virtual environment
python3.12 -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

# Install all dependencies including dev tools
pip install -e ".[dev]"
```

### Dependencies Overview

**Runtime dependencies** (`pyproject.toml`):

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >=0.109, <1.0 | Web framework |
| `uvicorn[standard]` | >=0.27, <1.0 | ASGI server |
| `sqlalchemy[asyncio]` | >=2.0.25, <3.0 | ORM (async) |
| `asyncpg` | >=0.29, <1.0 | PostgreSQL async driver |
| `alembic` | >=1.13, <2.0 | Database migrations |
| `pydantic-settings` | >=2.1, <3.0 | Configuration via env vars |
| `python-jose[cryptography]` | >=3.3, <4.0 | JWT tokens |
| `passlib[bcrypt]` | >=1.7.4, <2.0 | Password hashing |
| `celery` | >=5.3.6, <6.0 | Task queue |
| `redis` | >=5.0, <6.0 | Cache + Celery broker |
| `weasyprint` | >=61, <63 | PDF generation |
| `jinja2` | >=3.1.3, <4.0 | HTML templates |
| `boto3` | >=1.34, <2.0 | S3/MinIO object storage |
| `httpx` | >=0.26, <1.0 | HTTP client |
| `python-multipart` | >=0.0.6, <1.0 | Form data parsing |

**Dev dependencies:**

| Package | Purpose |
|---------|---------|
| `pytest` | Test framework |
| `pytest-asyncio` | Async test support |
| `httpx` | Test client |
| `factory-boy` | Test fixtures |
| `ruff` | Linter + formatter |

### Environment Variables

All configuration is via environment variables (or a `.env` file). See the [Configuration Reference](#13-configuration-reference) for the complete list.

Create a `.env` file in the `platform/` directory for local development:

```bash
# platform/.env

# Database
DATABASE_URL=postgresql+asyncpg://kubecomply:kubecomply@localhost:5432/kubecomply

# Redis
REDIS_URL=redis://localhost:6379/0

# Secrets (CHANGE THESE IN PRODUCTION)
SECRET_KEY=dev-secret-key-change-in-production
JWT_SECRET_KEY=dev-jwt-secret-change-in-production
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# S3/MinIO (local development)
S3_ENDPOINT_URL=http://localhost:9000
S3_ACCESS_KEY=kubecomply
S3_SECRET_KEY=devdevdevdev
S3_BUCKET_EVIDENCE=kubecomply-evidence
S3_BUCKET_SCANS=kubecomply-scans

# CORS
CORS_ORIGINS=["http://localhost:5173"]

# Environment
ENVIRONMENT=development
```

### Start the API Server

```bash
# Ensure PostgreSQL and Redis are running (via Docker Compose or locally)
# Then from the platform/ directory:

cd platform
source .venv/bin/activate

# Run with auto-reload
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# The API is now available at:
#   http://localhost:8000/api/docs     — Swagger UI
#   http://localhost:8000/api/redoc    — ReDoc
#   http://localhost:8000/healthz      — Health check
#   http://localhost:8000/readyz       — Readiness check
```

### API Endpoints Overview

All routes are under `/api/v1`:

| Endpoint Group | Prefix | Description |
|---------------|--------|-------------|
| Auth | `/api/v1/auth/` | Login, register, token refresh |
| Users | `/api/v1/users/` | User management |
| Organizations | `/api/v1/organizations/` | Org/tenant management |
| Clusters | `/api/v1/clusters/` | Kubernetes cluster registration |
| Scans | `/api/v1/scans/` | Scan results ingestion and queries |
| Evidence | `/api/v1/evidence/` | SOC 2 evidence packages |
| Drift | `/api/v1/drift/` | Compliance drift monitoring |
| Auditor | `/api/v1/auditor/` | Auditor collaboration portal |
| License | `/api/v1/license/` | License key management |
| Webhooks | `/api/v1/webhooks/` | Webhook management |

### Authentication Flow

1. **Register** → `POST /api/v1/auth/register` with `{email, password, full_name, org_name}`
2. **Login** → `POST /api/v1/auth/login` with `{email, password}`
3. Both return a `{access_token, refresh_token, expires_in}` response
4. Pass `Authorization: Bearer <access_token>` on subsequent requests
5. **Refresh** → `POST /api/v1/auth/refresh` with `{refresh_token}`

**User Roles:** `owner`, `admin`, `member`, `auditor`

---

## 9. React Frontend Setup — Compliance Dashboard UI

### Install Dependencies

```bash
cd platform/frontend

# Install all packages
npm install
```

### Development Server

```bash
npm run dev

# Starts Vite dev server at http://localhost:5173
# API calls to /api/* are proxied to http://localhost:8000
```

### Key Libraries

| Library | Purpose |
|---------|---------|
| `react` 18 + `react-dom` | UI framework |
| `react-router-dom` 6 | Client-side routing |
| `@tanstack/react-query` 5 | Server state management + caching |
| `axios` | HTTP client |
| `recharts` | Charts and data visualization |
| `zod` | Runtime schema validation |
| `react-hook-form` + `@hookform/resolvers` | Form management |
| `lucide-react` | Icon library |
| `tailwindcss` 3 + `tailwindcss-animate` | Utility-first CSS |
| `class-variance-authority` + `clsx` + `tailwind-merge` | Component variant styling |
| `react-syntax-highlighter` | YAML/JSON code highlighting |
| `date-fns` | Date formatting |

### Project Configuration

**Vite** (`vite.config.ts`):
- React plugin enabled
- `@/` path alias maps to `./src/`
- Dev server runs on port `5173`
- `/api` requests proxied to `http://localhost:8000`

**TypeScript** (`tsconfig.json`):
- Target: ES2020
- Strict mode enabled
- Path alias: `@/*` → `./src/*`

**Tailwind** (`tailwind.config.ts`):
- Dark mode via CSS class
- Custom colors for `severity` (critical/high/medium/low/info) and `compliance` (pass/fail/warn/skip)
- `tailwindcss-animate` plugin

### Build for Production

```bash
npm run build
# Output: platform/frontend/dist/

# Preview the production build
npm run preview
```

### Frontend Pages

| Page | Route | Description |
|------|-------|-------------|
| Login | `/login` | Authentication |
| Register | `/register` | New account creation |
| Dashboard | `/` | Overview with compliance scores |
| Scans | `/scans` | Scan history list |
| Scan Detail | `/scans/:id` | Individual scan results + findings |
| Drift | `/drift` | Compliance drift over time |
| Evidence List | `/evidence` | Evidence package list |
| Evidence Generator | `/evidence/generate` | Generate new evidence packages |
| Evidence Detail | `/evidence/:id` | Individual evidence package |
| Settings | `/settings` | User and org settings |
| Auditor Dashboard | `/auditor` | Auditor portal |
| Auditor Control | `/auditor/controls/:id` | Control review page |

---

## 10. Docker Compose — Run Full Stack Locally

### Services Overview

The development `docker-compose.yml` starts **7 services**:

| Service | Image | Port(s) | Purpose |
|---------|-------|---------|---------|
| `api` | `deploy/Dockerfile.api` | `8000` | FastAPI application |
| `worker` | `deploy/Dockerfile.worker` | — | Celery worker (queues: default, evidence, drift, alerts) |
| `beat` | `deploy/Dockerfile.worker` | — | Celery Beat scheduler |
| `frontend` | `deploy/Dockerfile.frontend` (dev) | `5173` | Vite dev server |
| `postgres` | `timescale/timescaledb:latest-pg16` | `5432` | PostgreSQL + TimescaleDB |
| `redis` | `redis:7-alpine` | `6379` | Celery broker + cache |
| `minio` | `minio/minio` | `9000`, `9001` | S3-compatible object storage |

Plus a one-shot `createbuckets` service that creates the MinIO buckets on first startup.

### Start / Stop / Manage

```bash
# Start all services (detached)
make docker-up
# Equivalent: docker compose -f deploy/docker-compose.yml up -d

# View logs
make docker-logs
# Equivalent: docker compose -f deploy/docker-compose.yml logs -f

# View logs for a specific service
docker compose -f deploy/docker-compose.yml logs -f api

# Stop all services
make docker-down
# Equivalent: docker compose -f deploy/docker-compose.yml down

# Rebuild images after code changes
make docker-build
# Equivalent: docker compose -f deploy/docker-compose.yml build

# Full restart
make docker-down && make docker-build && make docker-up

# Remove all data volumes (DESTRUCTIVE — deletes database, cache, files)
docker compose -f deploy/docker-compose.yml down -v
```

### Volume Mounts (Hot Reload)

In development mode, the API and worker mount the `platform/` directory:

```yaml
volumes:
  - ../platform:/app/platform
```

This means:
- **API changes** are automatically picked up by uvicorn's `--reload` flag
- **Worker changes** require a worker restart: `docker compose -f deploy/docker-compose.yml restart worker`
- **Frontend changes** are picked up by Vite's HMR

### Data Persistence

Three named volumes store persistent data:

| Volume | Service | Data |
|--------|---------|------|
| `pgdata` | PostgreSQL | Database tables and indexes |
| `redisdata` | Redis | Cache and Celery task state |
| `miniodata` | MinIO | Evidence PDFs and scan artifacts |

---

## 11. Kubernetes Deployment with Helm Chart

### Install from Cloned Repository

```bash
# Clone the repo
git clone https://github.com/nickfluxk/kubecomply.git
cd kubecomply

# Install with default values (OSS mode)
helm install kubecomply charts/kubecomply

# Install with custom values
helm install kubecomply charts/kubecomply -f values.yaml

# Install in a specific namespace
helm install kubecomply charts/kubecomply -n kubecomply --create-namespace
```

### Install from Local Chart

```bash
# Lint first
make helm-lint

# Template to review generated manifests
make helm-template

# Install from local directory
helm install kubecomply charts/kubecomply

# With custom values
helm install kubecomply charts/kubecomply \
  --set scanner.scanType=full \
  --set scanner.schedule="0 2 * * *" \
  --set metrics.serviceMonitor.enabled=true
```

### Helm Values Reference

| Parameter | Default | Description |
|-----------|---------|-------------|
| `replicaCount` | `1` | Number of agent pods |
| `image.repository` | `ghcr.io/nickfluxk/kubecomply` | Container image |
| `image.tag` | `""` (uses appVersion) | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Pull policy |
| `scanner.scanType` | `full` | Scan type: `cis`, `rbac`, `network`, `pss`, `full` |
| `scanner.schedule` | `""` | Cron schedule (empty = scan once) |
| `scanner.severityThreshold` | `info` | Minimum severity to report |
| `scanner.namespaces` | `[]` | Namespaces to scan (empty = all) |
| `scanner.customPolicies` | `[]` | Custom policy ConfigMap references |
| `rbac.create` | `true` | Create RBAC resources |
| `professional.enabled` | `false` | Enable SaaS integration |
| `professional.licenseKey` | `""` | License key (or use secret) |
| `professional.endpoint` | `https://api.kubecomply.io` | SaaS API endpoint |
| `dashboard.enabled` | `true` | Enable embedded dashboard |
| `dashboard.port` | `8080` | Dashboard port |
| `metrics.enabled` | `true` | Enable Prometheus metrics |
| `metrics.port` | `9090` | Metrics port |
| `metrics.serviceMonitor.enabled` | `false` | Create ServiceMonitor |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `384Mi` | Memory limit |
| `resources.requests.cpu` | `50m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |
| `logLevel` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logFormat` | `json` | Log format: `json`, `text` |
| `kubeApiQps` | `20` | K8s API QPS rate limit |
| `kubeApiBurst` | `30` | K8s API burst limit |

### Professional (Paid) Configuration

```bash
# Using Helm values file
helm install kubecomply charts/kubecomply -f examples/values-professional.yaml

# Using --set flags
helm install kubecomply charts/kubecomply \
  --set professional.enabled=true \
  --set professional.licenseKey="YOUR-LICENSE-KEY"

# Using a Kubernetes Secret for the license key
kubectl create secret generic kubecomply-license \
  --from-literal=license-key=YOUR-LICENSE-KEY

helm install kubecomply charts/kubecomply \
  --set professional.enabled=true \
  --set professional.licenseKeySecret.name=kubecomply-license \
  --set professional.licenseKeySecret.key=license-key
```

### Upgrade / Uninstall

```bash
# Upgrade
helm upgrade kubecomply charts/kubecomply -f values.yaml

# Uninstall (CRDs are NOT removed by default)
helm uninstall kubecomply

# Remove CRDs manually if desired
kubectl delete crd compliancescans.compliance.kubecomply.io
kubectl delete crd compliancepolicies.compliance.kubecomply.io
```

### Package the Chart

```bash
make helm-package
# Output: kubecomply-0.1.0.tgz
```

---

## 12. Custom Resource Definitions — ComplianceScan & CompliancePolicy CRDs

### ComplianceScan

The primary CRD for triggering and viewing compliance scans:

```yaml
apiVersion: compliance.kubecomply.io/v1alpha1
kind: ComplianceScan
metadata:
  name: daily-full-scan
  namespace: kubecomply
spec:
  # Scan type: cis, rbac, network, pss, full
  scanType: full

  # Cron schedule (empty = run once immediately)
  schedule: "0 2 * * *"   # Daily at 2 AM UTC

  # Namespaces to scan (empty = all non-system namespaces)
  namespaces:
    - production
    - staging

  # Minimum severity to report
  severityThreshold: medium   # critical, high, medium, low, info

  # Additional policy directories
  policyPaths:
    - /etc/kubecomply/custom-policies

  # Optional: SaaS integration
  saasIntegration:
    enabled: true
    licenseKeySecretRef:
      name: kubecomply-license
      key: license-key
    endpoint: https://api.kubecomply.io
```

**Status fields** (automatically populated):

```yaml
status:
  phase: Completed       # Pending, Running, Completed, Failed
  complianceScore: 87.5
  totalChecks: 94
  passedChecks: 82
  failedChecks: 12
  findings:
    critical: 2
    high: 5
    medium: 4
    low: 1
    info: 0
  lastScanTime: "2026-02-19T02:00:00Z"
  nextScanTime: "2026-02-20T02:00:00Z"
```

**Short name:** `cscan`

```bash
kubectl get cscan -A
# NAME              SCORE   PHASE       PASSED   FAILED   AGE
# daily-full-scan   87.5    Completed   82       12       1d
```

### CompliancePolicy

For adding custom Rego policies to the scan:

```yaml
apiVersion: compliance.kubecomply.io/v1alpha1
kind: CompliancePolicy
metadata:
  name: no-latest-tag
  namespace: kubecomply
spec:
  category: custom      # cis, nsa, rbac, pss, network, custom
  severity: medium       # critical, high, medium, low, info
  enabled: true

  # Inline Rego policy
  regoPolicy: |
    package custom.no_latest_tag
    # ... policy content ...

  # OR reference a ConfigMap
  regoPolicyConfigMapRef:
    name: my-policies
    key: no-latest-tag.rego
```

**Short name:** `cpol`

```bash
kubectl get cpol -A
```

---

## 13. Configuration Reference — Environment Variables & Settings

### API Environment Variables

All settings are defined in `platform/api/config.py` and can be overridden via environment variables or a `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| **Database** | | |
| `DATABASE_URL` | `postgresql+asyncpg://kubecomply:kubecomply@localhost:5432/kubecomply` | Async PostgreSQL connection URL |
| **Redis / Celery** | | |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL (broker + cache) |
| **Application Secrets** | | |
| `SECRET_KEY` | `change-me-in-production` | Application secret key |
| `JWT_SECRET_KEY` | `change-me-in-production-jwt` | JWT signing secret |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| **S3 / MinIO** | | |
| `S3_ENDPOINT_URL` | `None` | S3-compatible endpoint (set for MinIO, omit for AWS S3) |
| `S3_ACCESS_KEY` | `""` | S3 access key |
| `S3_SECRET_KEY` | `""` | S3 secret key |
| `S3_BUCKET_EVIDENCE` | `kubecomply-evidence` | Bucket for evidence PDFs |
| `S3_BUCKET_SCANS` | `kubecomply-scans` | Bucket for scan artifacts |
| **Email** | | |
| `EMAIL_FROM` | `noreply@kubecomply.io` | From address for emails |
| **CORS** | | |
| `CORS_ORIGINS` | `["http://localhost:3000", "http://localhost:5173"]` | Allowed CORS origins |
| **Environment** | | |
| `ENVIRONMENT` | `development` | `development` or `production` |

**Production note:** When `ENVIRONMENT=production`, Swagger UI (`/api/docs`), ReDoc (`/api/redoc`), and OpenAPI (`/api/openapi.json`) are disabled.

---

## 14. Database Migrations with Alembic (PostgreSQL)

KubeComply uses Alembic for database schema migrations with async PostgreSQL support.

### Setup

Alembic configuration lives in `platform/alembic.ini` and `platform/db/migrations/env.py`. The database URL is automatically injected from `api.config.Settings` — never hardcoded.

### Running Migrations

```bash
cd platform
source .venv/bin/activate

# Apply all pending migrations
make platform-migrate
# Equivalent: alembic upgrade head

# Apply migrations step by step
alembic upgrade +1

# Rollback one migration
alembic downgrade -1

# View current revision
alembic current

# View migration history
alembic history
```

### Creating New Migrations

```bash
# Auto-generate a migration from model changes
make platform-migrate-create MSG="add compliance score table"
# Equivalent: alembic revision --autogenerate -m "add compliance score table"

# Create an empty migration for manual SQL
alembic revision -m "add custom index"
```

### Migration File Naming

Files use the format: `YYYY_MM_DD_HHMM-<revision>_<slug>.py`

Example: `2026_02_19_1430-abc123_add_compliance_score_table.py`

### Offline Mode

Generate SQL without connecting to the database:

```bash
alembic upgrade head --sql > migration.sql
```

### Database Schema Overview

The platform uses a **multi-tenant** architecture with `org_id` on all tenant-scoped models. Key tables:

| Model | Table | Description |
|-------|-------|-------------|
| `Organization` | `organizations` | Tenant root (multi-org support) |
| `User` | `users` | User accounts with roles |
| `Cluster` | `clusters` | Registered K8s clusters |
| `Scan` | `scans` | Compliance scan results |
| `Evidence` | `evidence` | SOC 2 evidence packages |
| `CCControl` | `cc_controls` | SOC 2 CC control mappings |
| `ComplianceScore` | `compliance_scores` | Historical compliance scores |
| `Drift` | `drift` | Compliance drift events |
| `Auditor` | `auditors` | Auditor reviews/comments |
| `Alert` | `alerts` | Alert configurations |
| `AuditLog` | `audit_logs` | Audit trail |
| `License` | `licenses` | License keys |

All tenant models inherit from `TenantBase` which provides:
- `id` — UUID primary key (`gen_random_uuid()`)
- `org_id` — UUID foreign key (indexed)
- `created_at` — Auto-populated timestamp
- `updated_at` — Auto-updated timestamp

---

## 15. Background Workers — Celery Task Queue Setup

### Architecture

Celery is configured in `platform/workers/celery_app.py` with Redis as the broker and result backend.

**Task Queues:**

| Queue | Tasks | Purpose |
|-------|-------|---------|
| `default` | Executive digest | General-purpose |
| `evidence` | Evidence PDF generation | Heavy PDF rendering |
| `drift` | Drift detection | Event processing |
| `alerts` | Slack/PagerDuty/email dispatch | Time-sensitive |
| `scoring` | Daily compliance scoring | Batch processing |

**Periodic Schedules** (defined in `platform/workers/schedules.py`):

| Schedule | Task | Timing |
|----------|------|--------|
| Daily compliance scoring | `compute_daily_scores` | 02:00 UTC daily |
| Weekly executive digest | `send_weekly_digest` | Monday 08:00 UTC |
| Daily cleanup | `cleanup_old_data` | 03:30 UTC daily |

### Start Workers Manually

```bash
cd platform
source .venv/bin/activate

# Start a worker processing all queues
celery -A workers.celery_app worker -l info -Q default,evidence,drift,alerts,scoring

# Start just the evidence queue (for heavy PDF generation)
celery -A workers.celery_app worker -l info -Q evidence --concurrency=2

# Start the Beat scheduler (periodic tasks)
celery -A workers.celery_app beat -l info

# Monitor tasks
celery -A workers.celery_app flower   # Requires: pip install flower
```

### Configuration

Key Celery settings:

| Setting | Value | Description |
|---------|-------|-------------|
| `task_serializer` | `json` | Message serialization |
| `task_acks_late` | `true` | Acknowledge after completion |
| `worker_prefetch_multiplier` | `1` | Prevent greedy prefetch |
| `task_reject_on_worker_lost` | `true` | Re-queue on worker crash |
| `result_expires` | `86400` (24h) | Result retention |

---

## 16. Running Tests — Go, OPA, Python, and Frontend

### All Tests

```bash
# Run everything
make test
# Runs: agent-test, policy-test, platform-test, frontend-test, helm-lint
```

### Go Agent Tests

```bash
make agent-test
# Equivalent: cd agent && go test ./... -v -race

# With coverage
cd agent && go test ./... -v -race -coverprofile=coverage.out
go tool cover -html=coverage.out   # Open HTML report
```

### OPA Policy Tests

```bash
make policy-test
# Equivalent: opa test policies/ -v

# With coverage
opa test policies/ -v --coverage
```

### Python Platform Tests

```bash
make platform-test
# Equivalent: cd platform && pytest -v

# Run specific test file
cd platform && pytest api/tests/test_auth.py -v

# With coverage
cd platform && pytest --cov=api --cov-report=html
```

### Frontend Tests

```bash
make frontend-test
# Equivalent: cd platform/frontend && npm run test

# Watch mode
cd platform/frontend && npx vitest

# With coverage
cd platform/frontend && npx vitest run --coverage
```

### Helm Chart Tests

```bash
make helm-lint
# Equivalent: helm lint charts/kubecomply

# Template rendering (catches template errors)
make helm-template
# Equivalent: helm template kubecomply charts/kubecomply
```

---

## 17. Linting & Code Quality

### All Linters

```bash
make lint
# Runs: agent-lint, platform-lint, frontend-lint
```

### Go Linting

```bash
make agent-lint
# Equivalent: cd agent && golangci-lint run ./...
```

### Python Linting

```bash
make platform-lint
# Equivalent: cd platform && ruff check . && ruff format --check .

# Auto-fix issues
cd platform && ruff check . --fix
cd platform && ruff format .
```

**Ruff configuration** (in `pyproject.toml`):
- Target: Python 3.11
- Line length: 100
- Rules: E, F, I, N, W, UP, B, A, SIM, TCH
- Isort first-party: `api`, `db`, `workers`, `evidence_engine`

### Frontend Linting

```bash
make frontend-lint
# Equivalent: cd platform/frontend && npm run lint (ESLint)
```

### OPA Policy Formatting

```bash
make policy-fmt
# Equivalent: opa fmt -w policies/
```

---

## 18. Production Deployment — Kubernetes & Docker Compose

### Docker Compose (Production Overlay)

```bash
# Build production images
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml build

# Start with environment variables
export SECRET_KEY="$(openssl rand -hex 32)"
export JWT_SECRET_KEY="$(openssl rand -hex 32)"
export DATABASE_URL="postgresql+asyncpg://user:pass@db-host:5432/kubecomply"
export REDIS_URL="redis://redis-host:6379/0"
export S3_ACCESS_KEY="your-s3-key"
export S3_SECRET_KEY="your-s3-secret"
export CORS_ORIGINS='["https://your-domain.com"]'

docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.prod.yml up -d
```

**Production differences:**

| Setting | Development | Production |
|---------|------------|------------|
| API replicas | 1 | 2 |
| API workers | 1 (--reload) | 4 (uvicorn workers) |
| Worker concurrency | 1 | 4 |
| Celery log level | info | warning |
| Frontend | Vite dev server (port 5173) | Nginx serving static files (port 80/443) |
| API Docs | Enabled | Disabled |
| SQL echo | Enabled | Disabled |
| Resource limits | None | CPU + memory limits set |
| Health checks | None | HTTP health check on API |
| Restart policy | None | `always` |

### Resource Requirements (Production)

| Service | CPU Limit | Memory Limit | CPU Request | Memory Request |
|---------|----------|-------------|-------------|----------------|
| API (x2) | 1 core | 1 GB | 0.25 core | 256 MB |
| Worker (x2) | 2 cores | 2 GB | 0.5 core | 512 MB |
| Frontend | 0.5 core | 128 MB | — | — |

### Production Security Checklist

- [ ] Generate strong `SECRET_KEY` and `JWT_SECRET_KEY` (`openssl rand -hex 32`)
- [ ] Use managed PostgreSQL (RDS, Cloud SQL, etc.) with SSL
- [ ] Use managed Redis (ElastiCache, Memorystore) with TLS
- [ ] Use AWS S3 or equivalent (not MinIO) for evidence storage
- [ ] Set `ENVIRONMENT=production` to disable API docs
- [ ] Configure CORS origins to your specific domain(s)
- [ ] Set up TLS/HTTPS (via load balancer or cert-manager)
- [ ] Configure Sentry DSN for error tracking (optional)
- [ ] Enable PostgreSQL connection pooling (pgBouncer)
- [ ] Set up database backups
- [ ] Configure log aggregation (stdout → your log collector)
- [ ] Set resource limits and requests on all containers

### Kubernetes (Helm) Production

```bash
helm install kubecomply charts/kubecomply \
  --namespace kubecomply \
  --create-namespace \
  --set scanner.scanType=full \
  --set scanner.schedule="0 2 * * *" \
  --set scanner.severityThreshold=medium \
  --set metrics.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set resources.limits.memory=384Mi \
  --set resources.limits.cpu=500m \
  --set logLevel=info \
  --set logFormat=json
```

---

## 19. Security Model — Read-Only RBAC & Pod Security

### Agent RBAC (Read-Only)

The agent operates with **strictly read-only** Kubernetes API access:

| API Group | Resources | Verbs | Purpose |
|-----------|-----------|-------|---------|
| `""` (core) | pods, services, namespaces, nodes, serviceaccounts, configmaps | get, list, watch | Workload scanning |
| `""` (core) | secrets* | get, list, watch | Metadata only |
| `rbac.authorization.k8s.io` | roles, rolebindings, clusterroles, clusterrolebindings | get, list, watch | RBAC analysis |
| `networking.k8s.io` | networkpolicies, ingresses | get, list, watch | Network analysis |
| `apps` | deployments, daemonsets, statefulsets, replicasets | get, list, watch | Workload security |
| `admissionregistration.k8s.io` | webhookconfigurations | get, list | Change control |
| `policy` | poddisruptionbudgets | get, list | Availability |
| `autoscaling` | horizontalpodautoscalers | get, list | Scaling |
| `compliance.kubecomply.io` | compliancescans, compliancepolicies + /status | get, list, watch, create, update, patch | CRD management |

***Secrets:** The agent reads **metadata only** (name, namespace, labels, annotations, mount type). It **never** reads Secret `.data` fields. This is enforced in code with a CI test.

### Pod Security

The agent pod runs with hardened security settings:

```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 65534
  fsGroup: 65534

securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
```

### Resource Footprint

- Memory: <128Mi request, <384Mi limit
- CPU: <50m request, <500m limit
- No persistent storage needed
- No network egress required (unless SaaS integration is enabled)

---

## 20. Troubleshooting — Common Issues & Fixes

### Agent / CLI Issues

**"cannot connect to Kubernetes cluster"**
```bash
# Verify kubectl access
kubectl cluster-info

# Check kubeconfig path
echo $KUBECONFIG
ls -la ~/.kube/config

# Specify explicitly
kubecomply scan --kubeconfig ~/.kube/config
```

**"permission denied" errors during scan**
```bash
# Check the agent's ServiceAccount permissions
kubectl auth can-i list pods --as=system:serviceaccount:kubecomply:kubecomply

# Verify ClusterRole exists
kubectl get clusterrole kubecomply -o yaml

# Verify ClusterRoleBinding
kubectl get clusterrolebinding kubecomply -o yaml
```

**"no OPA policy modules loaded"**
```bash
# Check the policy directory exists and has .rego files
ls -la policies/

# Test policies independently
opa test policies/ -v

# When using the CLI, specify the path
kubecomply scan --policy-path ./policies
```

### Docker Compose Issues

**PostgreSQL won't start / health check fails**
```bash
# Check logs
docker compose -f deploy/docker-compose.yml logs postgres

# Reset the database volume
docker compose -f deploy/docker-compose.yml down
docker volume rm kubecomply_pgdata
docker compose -f deploy/docker-compose.yml up -d
```

**API can't connect to database**
```bash
# Verify PostgreSQL is healthy
docker compose -f deploy/docker-compose.yml ps postgres

# Check API environment
docker compose -f deploy/docker-compose.yml exec api env | grep DATABASE_URL

# Test connection manually
docker compose -f deploy/docker-compose.yml exec postgres psql -U kubecomply -c "SELECT 1"
```

**MinIO buckets not created**
```bash
# Check the createbuckets init container
docker compose -f deploy/docker-compose.yml logs createbuckets

# Create manually
docker compose -f deploy/docker-compose.yml exec minio mc alias set local http://localhost:9000 kubecomply devdevdevdev
docker compose -f deploy/docker-compose.yml exec minio mc mb local/kubecomply-evidence --ignore-existing
docker compose -f deploy/docker-compose.yml exec minio mc mb local/kubecomply-scans --ignore-existing
```

**Frontend can't reach API**
```bash
# Verify the API is running
curl http://localhost:8000/healthz

# Check Vite proxy config in platform/frontend/vite.config.ts
# The proxy should point to http://localhost:8000 for /api routes

# If running in Docker, the frontend proxies to the "api" container hostname
```

### Python Platform Issues

**"ModuleNotFoundError" when running API**
```bash
# Make sure you're in the virtual environment
source platform/.venv/bin/activate

# Reinstall dependencies
cd platform && pip install -e ".[dev]"
```

**WeasyPrint / PDF rendering fails**
```bash
# macOS
brew install cairo pango gdk-pixbuf libffi

# Ubuntu/Debian
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2 libffi-dev
```

**Alembic migration errors**
```bash
# Check current revision
cd platform && alembic current

# Check for broken migration chain
alembic history

# If corrupted, stamp current and re-migrate
alembic stamp head
```

### Helm / Kubernetes Issues

**CRDs not installed**
```bash
# Helm doesn't delete CRDs on uninstall. Apply manually:
kubectl apply -f charts/kubecomply/crds/

# Verify
kubectl get crd | grep kubecomply
```

**Agent pod crashing**
```bash
# Check logs
kubectl logs -l app.kubernetes.io/name=kubecomply -n kubecomply

# Check events
kubectl describe pod -l app.kubernetes.io/name=kubecomply -n kubecomply

# Common issue: OOM — increase memory limit
helm upgrade kubecomply charts/kubecomply --set resources.limits.memory=512Mi
```

---

## 21. FAQ — Frequently Asked Questions

### General

**Q: What is KubeComply?**

A: KubeComply is a Kubernetes-native compliance scanner that runs CIS Benchmark v1.9 (~150 checks), RBAC analysis, Pod Security Standards checks, and NetworkPolicy coverage analysis. The open-source agent runs inside your cluster with read-only access and provides actionable remediation guidance with exact YAML patches.

**Q: How is KubeComply different from kube-bench or Kubescape?**

A: Three key differences:
1. **Full CIS v1.9 coverage** with OPA/Rego policies you can read, modify, and extend
2. **Deep RBAC analysis** — not just "does ClusterAdmin exist?" but ClusterAdmin inventory, wildcard permissions, stale accounts, unused roles
3. **NetworkPolicy coverage percentage** per namespace, not just "do policies exist?"
4. **Remediation YAML** — every finding includes the exact YAML patch to fix it

**Q: Is KubeComply free?**

A: The open-source agent (CIS scanning, RBAC analysis, PSS checks, NetworkPolicy coverage, CLI, dashboard, Prometheus metrics) is **free forever** under Apache 2.0. KubeComply Professional adds SOC 2 evidence packages, auditor portal, drift monitoring, and executive digests as a commercial offering.

**Q: What compliance frameworks does KubeComply support?**

A: OSS: CIS Kubernetes Benchmark v1.9, NSA/CISA Hardening Guide, Pod Security Standards (Baseline + Restricted). Professional: SOC 2 Type II (CC6, CC7, CC8, A1 control families).

**Q: Does KubeComply modify my cluster?**

A: No. The agent uses **strictly read-only** Kubernetes API access. It never creates, updates, or deletes any resources in your cluster (except its own ComplianceScan status updates). The ClusterRole has only `get`, `list`, and `watch` verbs on cluster resources.

**Q: Does KubeComply read my Secrets?**

A: It reads Secret **metadata only** (name, namespace, labels, annotations, type). It **never** reads the `.data` field containing actual secret values. This is enforced in code with a build-failing CI test.

---

### Installation & Setup

**Q: What are the minimum system requirements for the CLI?**

A: Go 1.22+ for building, or just the pre-built binary. The CLI connects to any Kubernetes cluster via kubeconfig and needs `kubectl` level access.

**Q: What are the minimum Kubernetes version requirements?**

A: Kubernetes 1.28 or later. The agent uses `client-go` v0.31.0 which supports Kubernetes 1.28+.

**Q: Can I run KubeComply without Helm?**

A: Yes! You can:
1. Use the CLI directly: `kubecomply scan --format table`
2. Apply the Kubernetes manifests manually (render them with `helm template`)
3. Use `kubectl apply -f` on the CRD manifests + deployment YAML

**Q: Can I run KubeComply outside a Kubernetes cluster?**

A: Yes. The CLI works from any machine with kubeconfig access:
```bash
kubecomply scan --kubeconfig ~/.kube/config --format table
```

**Q: Do I need Docker to use KubeComply?**

A: No. Docker is only needed for:
- Building container images
- Running the SaaS platform locally (via Docker Compose)
The CLI and agent can be built and run without Docker.

**Q: How do I install on an air-gapped system?**

A:
1. Build the binary on a connected machine: `make cli`
2. Copy `agent/bin/kubecomply` to the air-gapped system
3. Copy the `policies/` directory for OPA policy evaluation
4. Run: `kubecomply scan --policy-path ./policies --format table`

For the container image, push `ghcr.io/nickfluxk/kubecomply:<version>` to your private registry.

---

### Development

**Q: How do I set up the full development environment?**

A: Follow these steps:
```bash
# 1. Clone
git clone https://github.com/nickfluxk/kubecomply.git && cd kubecomply

# 2. Start infrastructure (PostgreSQL, Redis, MinIO)
docker compose -f deploy/docker-compose.yml up -d postgres redis minio createbuckets

# 3. Set up Go agent
cd agent && go mod download && cd ..

# 4. Set up Python platform
cd platform && python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
alembic upgrade head
cd ..

# 5. Set up Frontend
cd platform/frontend && npm install && cd ../..

# 6. Start services (in separate terminals)
# Terminal 1: API
cd platform && uvicorn api.main:app --reload --port 8000

# Terminal 2: Worker
cd platform && celery -A workers.celery_app worker -l info -Q default,evidence,drift,alerts

# Terminal 3: Frontend
cd platform/frontend && npm run dev
```

**Q: How do I run only the parts I'm working on?**

A:
- **Agent/CLI only:** `make cli && ./agent/bin/kubecomply scan`
- **Policies only:** `opa test policies/ -v`
- **API only:** `docker compose up postgres redis` + `uvicorn api.main:app --reload`
- **Frontend only:** `npm run dev` (needs API running for data)

**Q: What's the commit message convention?**

A: Conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding or updating tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `chore:` Build process or tooling changes

**Q: How do I add a new API endpoint?**

A:
1. Create a new module under `platform/api/<domain>/`
2. Add `router.py` (FastAPI router), `schemas.py` (Pydantic models), `service.py` (business logic)
3. Register the router in `platform/api/main.py` → `create_app()`
4. Add database models in `platform/db/models/` if needed
5. Generate a migration: `alembic revision --autogenerate -m "description"`
6. Run the migration: `alembic upgrade head`

**Q: How do I add a new compliance check?**

A: See [Section 7: OPA/Rego Policies](#7-oparego-policy-development--writing-custom-compliance-rules). In short:
1. Create a `.rego` file in the appropriate `policies/` subdirectory
2. Use the `lib.helpers` result builders for consistent output
3. Write a `_test.rego` file alongside it
4. Run `make policy-test` to verify

**Q: How do I regenerate CRD manifests after changing Go types?**

A:
```bash
cd agent && make generate
```
This runs `controller-gen` to update:
- `agent/api/v1alpha1/zz_generated.deepcopy.go`
- `charts/kubecomply/crds/compliancescan.yaml`
- `charts/kubecomply/crds/compliancepolicy.yaml`

---

### Configuration

**Q: How do I configure the scan schedule?**

A: Via Helm values or the ComplianceScan CRD:
```yaml
# Helm values
scanner:
  schedule: "0 2 * * *"  # Daily at 2 AM UTC

# ComplianceScan CR
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
```
Empty schedule means the scan runs once immediately.

**Q: How do I scan only specific namespaces?**

A:
```bash
# CLI
kubecomply scan --namespace production

# Helm
helm install kubecomply charts/kubecomply --set scanner.namespaces={production,staging}

# ComplianceScan CR
spec:
  namespaces:
    - production
    - staging
```

**Q: How do I exclude system namespaces?**

A: By default, `kube-system`, `kube-public`, and `kube-node-lease` are excluded from all scans. To include them, you must explicitly list them in the namespace filter.

**Q: How do I change the database used by the platform?**

A: Set the `DATABASE_URL` environment variable. The platform uses **async PostgreSQL** (via `asyncpg`). The URL format is:
```
postgresql+asyncpg://user:password@host:port/database
```
TimescaleDB is recommended for time-series compliance score data but standard PostgreSQL 16+ works fine.

**Q: Can I use MySQL instead of PostgreSQL?**

A: No. The platform relies on PostgreSQL-specific features:
- `gen_random_uuid()` for UUID primary keys
- `asyncpg` for async database access
- PostgreSQL's `JSONB` type for scan results
- TimescaleDB extensions for time-series data (optional)

**Q: How do I configure S3 for production (AWS)?**

A: Set these environment variables:
```bash
S3_ENDPOINT_URL=         # Leave empty for AWS S3 (boto3 default)
S3_ACCESS_KEY=AKIA...    # AWS access key (or use IAM role)
S3_SECRET_KEY=...        # AWS secret key
S3_BUCKET_EVIDENCE=your-evidence-bucket
S3_BUCKET_SCANS=your-scans-bucket
```
For IAM roles (ECS/EKS), leave `S3_ACCESS_KEY` and `S3_SECRET_KEY` empty — boto3 will use the instance role automatically.

---

### Monitoring & Operations

**Q: How do I enable Prometheus metrics?**

A: Metrics are enabled by default on the agent. For ServiceMonitor:
```bash
helm install kubecomply charts/kubecomply \
  --set metrics.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.interval=30s
```

**Q: What metrics does KubeComply expose?**

A: The agent exposes standard Prometheus metrics at `/metrics` on the configured port (default 9090), including:
- Compliance score (gauge)
- Findings by severity (gauge)
- Scan duration (histogram)
- Scan status (counter)
- API request latency (histogram, SaaS mode)

**Q: How do I view the embedded dashboard?**

A: When `dashboard.enabled=true` (default), access the dashboard at:
- Helm: `http://<agent-service>:8080/dashboard/`
- Port-forward: `kubectl port-forward svc/kubecomply 8080:8080 && open http://localhost:8080/dashboard/`

The dashboard JSON API is at:
- `GET /api/v1/scans/latest` — Latest scan results
- `GET /api/v1/health` — Agent health check

**Q: How do I set up alerts?**

A: (Professional only) Configure alert channels in the platform UI under Settings > Alerts. Supported channels:
- Slack
- PagerDuty
- Email
- Jira

Alerts are dispatched by the `alert_dispatch` Celery worker.

---

### Troubleshooting

**Q: The scan shows 0 findings. What's wrong?**

A: Most likely:
1. **No policies loaded.** Run with `--policy-path ./policies` or check that the `policy-dir` flag is set for the operator
2. **All checks pass.** This is a good thing! Check the scan summary for pass counts
3. **Namespace filter too restrictive.** Try without `--namespace` to scan all namespaces
4. **Wrong scan type.** `--scan-type cis` only runs CIS checks, not RBAC/network/PSS

**Q: The agent keeps crashing with OOMKilled.**

A: Increase the memory limit:
```bash
helm upgrade kubecomply charts/kubecomply --set resources.limits.memory=512Mi
```
Large clusters (500+ pods) may need 384-512Mi.

**Q: Database migrations fail with "relation already exists".**

A: The migration state may be out of sync:
```bash
cd platform
alembic current          # Check current revision
alembic stamp head       # Force-stamp to latest
alembic upgrade head     # Re-run migrations
```

**Q: The frontend shows "Network Error" on every API call.**

A: Check that:
1. The API is running on port 8000
2. Vite's proxy config targets `http://localhost:8000` (see `vite.config.ts`)
3. CORS origins include `http://localhost:5173`
4. The API's health endpoint responds: `curl http://localhost:8000/healthz`

**Q: How do I reset the local development environment?**

A:
```bash
# Nuclear option — removes all containers, volumes, and data
docker compose -f deploy/docker-compose.yml down -v

# Restart fresh
docker compose -f deploy/docker-compose.yml up -d

# Re-run migrations
cd platform && alembic upgrade head
```

**Q: How do I debug a specific Rego policy?**

A:
```bash
# Evaluate a policy with test input
opa eval -d policies/ -i test-input.json "data.pss.baseline.results"

# Print debug trace
opa eval -d policies/ -i test-input.json "data.pss.baseline.results" --explain full

# Interactive REPL
opa run policies/ -i test-input.json
```

**Q: Why does my scan take a long time?**

A: Scan time scales with cluster size. Optimizations:
1. Scan specific namespaces: `--namespace production`
2. Use a specific scan type: `--scan-type rbac` instead of `full`
3. Increase K8s API rate limits in Helm values: `kubeApiQps: 50`, `kubeApiBurst: 100`
4. Increase the agent's CPU request for faster OPA evaluation

**Q: Can I run multiple KubeComply agents in the same cluster?**

A: Yes, but use leader election to avoid duplicate scans:
```bash
helm install kubecomply charts/kubecomply \
  --set replicaCount=2
```
The operator uses leader election (via `--leader-elect`) to ensure only one active controller.

---

## Appendix: Makefile Quick Reference

```bash
# ── Top-level ──────────────────────
make all                   # Build agent + CLI + platform + frontend
make clean                 # Remove all build artifacts
make test                  # Run ALL tests (Go, Rego, Python, JS, Helm)
make lint                  # Run ALL linters

# ── Go Agent ───────────────────────
make agent                 # Build operator agent binary
make cli                   # Build CLI binary
make agent-test            # Go tests with race detection
make agent-lint            # golangci-lint

# ── OPA Policies ───────────────────
make policy-test           # OPA policy tests
make policy-fmt            # Format Rego files

# ── Python Platform ────────────────
make platform-install      # pip install -e ".[dev]"
make platform-test         # pytest
make platform-lint         # ruff check + format check
make platform-migrate      # alembic upgrade head
make platform-migrate-create MSG="msg"  # Generate migration

# ── Frontend ───────────────────────
make frontend-install      # npm install
make frontend              # Production build (tsc + vite)
make frontend-dev          # Vite dev server
make frontend-lint         # ESLint
make frontend-test         # vitest

# ── Helm ───────────────────────────
make helm-lint             # Lint chart
make helm-template         # Render templates
make helm-package          # Package chart

# ── Docker ─────────────────────────
make docker-build          # Build all images
make docker-up             # Start all services
make docker-down           # Stop all services
make docker-logs           # Follow all logs
```

---

## Appendix: KubeComply vs Other Kubernetes Security Scanners

| Feature | KubeComply (OSS) | kube-bench | Kubescape | Trivy Operator |
|---------|-----------------|------------|-----------|---------------|
| CIS Benchmark v1.9 | ~150 checks | ~150 checks | Partial | Partial |
| RBAC Deep Analysis | ClusterAdmin, wildcards, stale accounts, unused roles | No | Basic | No |
| NetworkPolicy Coverage (%) | Per-namespace percentage | No | Basic | No |
| Pod Security Standards | Baseline + Restricted | No | Yes | Yes |
| Custom OPA/Rego Policies | Full support | No | Partial (Rego) | No |
| Remediation YAML Patches | Every finding | No | Some | No |
| Kubernetes Operator (CRD) | Yes | No | Yes | Yes |
| CLI Tool | Yes | Yes | Yes | Yes |
| Helm Chart | Yes | Yes | Yes | Yes |
| Prometheus Metrics | Yes | No | Yes | Yes |
| Embedded Dashboard | Yes | No | Yes | No |
| SOC 2 Evidence (Professional) | CC6-CC9 + A1 | No | No | No |
| Auditor Collaboration | Yes (Professional) | No | No | No |
| License | Apache 2.0 | Apache 2.0 | Apache 2.0 | Apache 2.0 |
| Resource Footprint | <128Mi, <50m CPU | Low | ~256Mi | ~256Mi |

---

## Related Topics

This guide covers setup and configuration for the following Kubernetes security and compliance topics:

- **CIS Kubernetes Benchmark v1.9** — How to run CIS compliance checks against your Kubernetes cluster
- **Kubernetes RBAC security audit** — Detecting ClusterAdmin bindings, wildcard permissions, stale service accounts
- **Pod Security Standards enforcement** — Baseline and Restricted profile validation for Kubernetes workloads
- **Kubernetes NetworkPolicy coverage analysis** — Measuring per-namespace NetworkPolicy coverage percentage
- **OPA/Rego policies for Kubernetes** — Writing and testing custom compliance rules with Open Policy Agent
- **SOC 2 Type II compliance for Kubernetes** — Generating auditor-ready evidence packages for CC6, CC7, CC8, A1 controls
- **Kubernetes compliance scanning with Helm** — Deploying automated compliance scans via Helm chart
- **Kubernetes security scanner comparison** — KubeComply vs kube-bench vs Kubescape vs Trivy
- **Kubernetes compliance as code** — Infrastructure compliance automation with OPA/Rego
- **Kubernetes security best practices** — RBAC least privilege, NetworkPolicy default deny, Pod Security Standards
