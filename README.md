<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=1000&color=00D9FF&center=true&vCenter=true&width=600&lines=🛡️+Sentinel+AI;DevSecOps+Pipeline+Orchestrator;Security+%2B+AI+%2B+Automation" alt="Sentinel AI"/>

<br/>

**AI-powered DevSecOps security pipeline with local Ollama AI triage and real-time dashboard**

<br/>

[![Security Pipeline](https://github.com/MuhammadAliRaza-DevSecOps/sentinel-ai/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/MuhammadAliRaza-DevSecOps/sentinel-ai/actions)
[![CodeQL](https://github.com/MuhammadAliRaza-DevSecOps/sentinel-ai/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/MuhammadAliRaza-DevSecOps/sentinel-ai/actions)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker&logoColor=white)
![Ollama](https://img.shields.io/badge/AI-Ollama%20phi3:mini-FF6B35?style=flat&logo=ollama&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat)
![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen?style=flat)

<br/>

[🚀 Quick Start](#-quick-start) · [🏗️ Architecture](#️-architecture) · [✨ Features](#-features) · [📊 Dashboard](#-dashboard) · [🤝 Contributing](#-contributing)

</div>

---

## 🎯 Problem Statement

> Security vulnerabilities cost organizations **$4.45M per breach** (IBM 2023).
> Most breaches are **preventable** — caught by static analysis.
> Yet **73% of organizations** scan manually, late in the cycle when fixes are **10× more expensive**.

---

## 💡 Solution

**Sentinel AI** shifts security **left** — catching vulnerabilities at `git push` time, not after deployment.
Developer pushes code
↓
GitHub Actions triggers automatically
↓
5 scanners run in parallel
↓
Ollama AI triages findings locally
↓
Pass ✅ or Block ❌ the merge
↓
Dashboard shows trends

---

## ✨ Features

| Feature | Tool | What it catches |
|---------|------|-----------------|
| 🔑 Secret Detection | Gitleaks + trufflehog | API keys, passwords, tokens |
| 🔍 SAST | Semgrep + Bandit | SQLi, XSS, command injection |
| 📦 SCA | Safety + pip-audit | CVEs in dependencies |
| 🐳 Container Security | Trivy | OS + package vulnerabilities |
| 🌐 DAST | OWASP ZAP | Runtime vulnerabilities |
| 🤖 AI Triage | Ollama phi3:mini | False positive reduction |
| 📊 Dashboard | Streamlit | Real-time trends + reports |
| 📧 Notifications | SMTP + Slack | Instant alerts |

---

## 🏗️ Architecture
┌─────────────────────────────────────────────────────┐
│                   Developer Machine                  │
│  ┌──────────┐    git push    ┌──────────────────┐   │
│  │   Code   │ ─────────────► │   GitHub Repo    │   │
│  └──────────┘                └────────┬─────────┘   │
└───────────────────────────────────────┼─────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│              GitHub Actions Pipeline                 │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  Secret  │  │   SAST   │  │       SCA        │  │
│  │  Scan   │  │ Semgrep  │  │ Safety+pip-audit  │  │
│  │Gitleaks │  │ +Bandit  │  │                  │  │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
│       │             │                  │             │
│  ┌────┴─────────────┴──────────────────┴──────────┐ │
│  │           Scoring Engine (CVSS)                │ │
│  └────────────────────┬───────────────────────────┘ │
│                       │                             │
│  ┌────────────────────▼───────────────────────────┐ │
│  │         Ollama AI Triage (phi3:mini)           │ │
│  │         Local — No data leaves machine         │ │
│  └────────────────────┬───────────────────────────┘ │
│                       │                             │
│            ┌──────────┴──────────┐                  │
│            ▼                     ▼                  │
│      ┌──────────┐         ┌──────────┐              │
│      │  PASS ✅  │         │  FAIL ❌  │              │
│      │  Merge   │         │  Block   │              │
│      └──────────┘         └──────────┘              │
└─────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────┐
│                  Local Services                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ FastAPI  │  │PostgreSQL│  │    Streamlit     │  │
│  │  :8000  │  │  :5432   │  │   Dashboard      │  │
│  └──────────┘  └──────────┘  │     :8501        │  │
│                               └──────────────────┘  │
└─────────────────────────────────────────────────────┘

---

## 🚀 Quick Start

### Prerequisites

```bash
# Required
Python 3.11+
Docker Desktop
Git
Ollama (https://ollama.ai)

# Install Ollama model
ollama pull phi3:mini
```

### Installation

```bash
# 1. Clone karo
git clone https://github.com/MuhammadAliRaza-DevSecOps/sentinel-ai.git
cd sentinel-ai

# 2. Environment setup
cp .env.example .env
# .env mein apni values fill karo

# 3. Virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac

# 4. Dependencies
pip install -r requirements.txt

# 5. Docker se start karo
docker-compose up -d --build
```

### Access

| Service | URL |
|---------|-----|
| 📊 Dashboard | http://localhost:8501 |
| 🔌 API Docs | http://localhost:8000/docs |
| ❤️ Health Check | http://localhost:8000/health |

---

## 📊 Dashboard
┌─────────────────────────────────────────┐
│  🛡️ Sentinel AI Dashboard               │
├──────────┬──────────┬──────────┬────────┤
│ Total    │ Passed   │ Critical │  High  │
│   47     │  38 (80%)│    2     │   8    │
├──────────┴──────────┴──────────┴────────┤
│  [Pie Chart]    [Trend Line Chart]      │
├─────────────────────────────────────────┤
│  Recent Findings Table                  │
│  ✅ main · sast · C:0 H:2 · 2025-05-12 │
│  ❌ feat · full · C:1 H:3 · 2025-05-11 │
└─────────────────────────────────────────┘

---

## 🔧 Tech Stack
Backend    │ FastAPI + PostgreSQL + Redis + Celery
Frontend   │ Streamlit + Plotly
AI         │ Ollama phi3:mini (100% local)
Scanners   │ Semgrep, Bandit, Trivy, Gitleaks, OWASP ZAP
CI/CD      │ GitHub Actions
Container  │ Docker + Docker Compose

---

## 📁 Project Structure
sentinel-ai/
├── .github/
│   ├── workflows/
│   │   ├── security-pipeline.yml   # Main CI/CD
│   │   └── codeql-analysis.yml     # CodeQL scan
│   └── ISSUE_TEMPLATE/
├── scanner/
│   ├── sast_scanner.py             # Semgrep + Bandit
│   ├── secret_scanner.py           # Gitleaks + trufflehog
│   ├── sca_scanner.py              # Safety + pip-audit
│   ├── container_scanner.py        # Trivy
│   ├── dast_scanner.py             # OWASP ZAP
│   ├── scoring_engine.py           # CVSS scoring
│   └── ai_triage.py                # Ollama AI
├── api/
│   ├── main.py                     # FastAPI app
│   ├── database.py                 # PostgreSQL
│   └── routes/
├── dashboard/
│   ├── app.py                      # Streamlit main
│   └── pages/
├── notifications/
├── reports/
├── tests/
├── docker/
├── k8s/
├── docker-compose.yml
├── requirements.txt
└── .env.example

---

## 🧪 Testing

```bash
# All tests run karo
pytest tests/ -v

# Coverage check
pytest tests/ --cov=scanner --cov-report=html

# Local scan run karo
./scripts/run_local_scan.sh .
```

---

## 🤝 Contributing

Contributions welcome! Dekho [CONTRIBUTING.md](CONTRIBUTING.md)

```bash
# Feature branch banao
git checkout -b feat/your-feature

# Changes karo aur commit karo
git commit -m "feat: add your feature"

# Push karo
git push origin feat/your-feature

# Pull Request kholo
```

---

## 📄 License

MIT License — dekho [LICENSE](LICENSE)

---

## 👨‍💻 Author

**Muhammad Ali Raza**

[![GitHub](https://img.shields.io/badge/GitHub-MuhammadAliRaza--DevSecOps-181717?style=flat&logo=github)](https://github.com/MuhammadAliRaza-DevSecOps)

---

<div align="center">

**⭐ Agar project pasand aaya to star zaroor dein!**

Made with ❤️ for the cybersecurity community

</div>