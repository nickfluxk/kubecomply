# Contributing to KubeComply

Thank you for your interest in contributing to KubeComply! This guide will help you get started.

## License

KubeComply is licensed under Apache 2.0. No CLA is required. By contributing, you agree that your contributions will be licensed under the same license.

## What Can I Contribute?

### OPA/Rego Policies (Most Welcome!)
- New CIS benchmark checks
- NSA/CISA hardening guide checks
- Custom compliance policies
- Policy improvements and false positive fixes

### Agent Improvements
- New scanner capabilities
- Performance optimizations
- Bug fixes
- Documentation

### Documentation
- Usage guides
- Policy documentation
- Architecture docs

## Getting Started

### Prerequisites
- Go 1.22+
- OPA CLI (`brew install opa`)
- Helm 3
- Docker + Docker Compose
- Node.js 20+ (for frontend development)
- Python 3.12+ (for platform development)

### Development Setup

```bash
# Clone the repo
git clone https://github.com/nickfluxk/kubecomply.git
cd kubecomply

# Build the agent
make agent

# Build the CLI
make cli

# Run OPA policy tests
make policy-test

# Start the full platform (requires Docker)
make docker-up
```

### Adding a New Rego Policy

1. Create your policy file in the appropriate directory under `policies/`
2. Every policy must include:
   - `check_id`: Unique identifier (e.g., `KC-CIS-1.2.1`)
   - `title`: Human-readable check name
   - `description`: What this check verifies
   - `severity`: `critical`, `high`, `medium`, `low`, or `info`
   - `remediation`: YAML patch or instructions to fix
3. Write tests in a `_test.rego` file alongside your policy
4. Run `make policy-test` to verify

### Commit Messages

We use conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding or updating tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `chore:` Build process or tooling changes

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit your changes with conventional commit messages
4. Push to your fork
5. Open a Pull Request against `main`
6. Ensure CI passes (go test, rego test, helm lint)

## Security

The agent uses **read-only** Kubernetes API access. If your contribution requires additional RBAC permissions, it will need thorough security review. See [SECURITY.md](SECURITY.md) for details.

**Critical rule:** No code path may read a Secret's `.data` field. A CI test enforces this.

## Questions?

- Open a GitHub Discussion
- Join our community Slack
