.PHONY: all build test lint clean agent cli platform frontend helm docker

VERSION ?= 0.1.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

# ──────────────── Top-level ────────────────

all: agent cli platform frontend

clean:
	rm -rf agent/bin/ platform/frontend/dist/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# ──────────────── Go Agent ────────────────

agent:
	cd agent && go build -ldflags "$(LDFLAGS)" -o bin/kubecomply-agent ./cmd/agent

cli:
	cd agent && go build -ldflags "$(LDFLAGS)" -o bin/kubecomply ./cmd/cli

agent-test:
	cd agent && go test ./... -v -race

agent-lint:
	cd agent && golangci-lint run ./...

# ──────────────── OPA Policies ────────────────

policy-test:
	opa test policies/ -v

policy-fmt:
	opa fmt -w policies/

# ──────────────── Python Platform ────────────────

platform-install:
	cd platform && pip install -e ".[dev]"

platform-test:
	cd platform && pytest -v

platform-lint:
	cd platform && ruff check . && ruff format --check .

platform-migrate:
	cd platform && alembic upgrade head

platform-migrate-create:
	cd platform && alembic revision --autogenerate -m "$(MSG)"

# ──────────────── Frontend ────────────────

frontend-install:
	cd platform/frontend && npm install

frontend:
	cd platform/frontend && npm run build

frontend-dev:
	cd platform/frontend && npm run dev

frontend-lint:
	cd platform/frontend && npm run lint

frontend-test:
	cd platform/frontend && npm run test

# ──────────────── Helm ────────────────

helm-lint:
	helm lint charts/kubecomply

helm-template:
	helm template kubecomply charts/kubecomply

helm-package:
	helm package charts/kubecomply

# ──────────────── Docker ────────────────

docker-build:
	docker compose -f deploy/docker-compose.yml build

docker-up:
	docker compose -f deploy/docker-compose.yml up -d

docker-down:
	docker compose -f deploy/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f

# ──────────────── Full Test Suite ────────────────

test: agent-test policy-test platform-test frontend-test helm-lint
	@echo "All tests passed"

lint: agent-lint platform-lint frontend-lint
	@echo "All linting passed"
