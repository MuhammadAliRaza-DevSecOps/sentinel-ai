<!-- README.md -->
<!-- This is what people see when they visit your GitHub repository -->
<!-- A great README is the difference between 0 stars and 500 stars -->

<div align="center">

# 🛡️ DevSecOps Pipeline Orchestrator

**Automated security scanning pipeline with AI-powered triage and real-time dashboard**

[![Security Pipeline](https://github.com/yourusername/devsecops-pipeline-orchestrator/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/yourusername/devsecops-pipeline-orchestrator/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED.svg)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Demo](#demo) · [Quick Start](#quick-start) · [Architecture](#architecture) · [Documentation](#documentation)

</div>

---

## Problem Statement

Security vulnerabilities cost organizations an average of **$4.45M per breach** (IBM 2023). 
Most breaches are preventable — they exploit vulnerabilities that static analysis would catch. 
Yet **73% of organizations** run security scans manually, late in the development cycle when fixes are 10× more expensive.

## Solution

DevSecOps Pipeline Orchestrator shifts security **left** — catching vulnerabilities at `git push` time, 
not after deployment. It combines 5 scanning tools, AI-powered triage, and a real-time dashboard.

## Features

| Feature | Tool | What it catches |
|---------|------|-----------------|
| Secret Detection | Gitleaks + trufflehog | API keys, passwords, tokens in code/history |
| SAST | Semgrep + Bandit | SQLi, XSS, command injection, insecure patterns |
| SCA | Safety + pip-audit | CVEs in Python dependencies |
| Container Security | Trivy | OS and package vulnerabilities in Docker images |
| DAST | OWASP ZAP | Runtime vulnerabilities in running applications |

## Architecture

![Architecture Diagram](docs/architecture.png)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/devsecops-pipeline-orchestrator
cd devsecops-pipeline-orchestrator

# Copy environment file and configure
cp .env.example .env
# Edit .env with your settings

# Start everything with Docker Compose
docker-compose up -d --build

# Open the dashboard
open http://localhost:8501
```

## GitHub Actions Integration

Add this to any repository to enable automated scanning:

```yaml
# .github/workflows/security.yml
jobs:
  security:
    uses: yourusername/devsecops-pipeline-orchestrator/.github/workflows/security-pipeline.yml@main
    secrets: inherit
```

## Roadmap

- [x] SAST scanning (Semgrep + Bandit)
- [x] Container scanning (Trivy)
- [x] Secret detection (Gitleaks)
- [x] Streamlit dashboard
- [x] GitHub Actions pipeline
- [ ] AI-powered false positive reduction
- [ ] Kubernetes operator
- [ ] Slack/Teams integration
- [ ] SBOM generation

## License

MIT — see [LICENSE](LICENSE)