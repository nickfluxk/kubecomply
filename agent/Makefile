.PHONY: build build-cli test lint clean generate

VERSION ?= 0.1.0
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o bin/kubecomply-agent ./cmd/agent

build-cli:
	go build -ldflags "$(LDFLAGS)" -o bin/kubecomply ./cmd/cli

test:
	go test ./... -v -race -coverprofile=coverage.out

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out

generate:
	controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./..."
	controller-gen crd paths="./..." output:crd:artifacts:config=../charts/kubecomply/crds
