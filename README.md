# 🇳🇵 Nepal SBOM Scanner

**The Ultimate AI-Powered Security & Compliance Platform for South Asian SaaS.**

Nepal SBOM Scanner is a professional-grade security tool that helps you secure your software supply chain. It generates compliance-ready SBOMs, identifies vulnerabilities in dependencies, audits your source code for secrets, and provides AI-powered remediation strategies with automated Pull Requests.

---

## 🔥 Key Features

- **🚀 3-Channel Scanning:** Support for local ZIP uploads, Public GitHub repositories, and Private GitHub repositories (via OAuth).
- **🧠 AI Remediation:** Integrated with Groq (Llama-3) to provide instant, actionable security patches for every vulnerability found.
- **🤖 Auto-Fix PR Bot:** Automatically creates GitHub branches and opens Pull Requests to upgrade vulnerable packages.
- **🔍 Deep Code Audit:** Static Analysis (SAST) to find hardcoded secrets (API keys, AWS keys) and dangerous code patterns (Command Injection, Insecure Deserialization).
- **📄 Compliance Ready:** One-click generation of **SPDX 2.3** SBOMs for international regulatory compliance.
- **📊 Professional Dashboard:** Premium glassmorphism UI with Security Grading (A-F), Audit Logs, and Executive Summaries.
- **🏗️ CI/CD Integration:** Includes a production-ready CLI tool for automated security gating in your build pipelines.

---

## 🛠️ Tech Stack

- **Backend:** FastAPI, Uvicorn, SQLite
- **AI Engine:** Groq LLM (AI-Remediation & Caching)
- **Frontend:** Vanilla JS, Tailwind CSS, Lucide Icons
- **Scanning:** OSV.dev Database, Custom SAST Engine

---

## 🚀 Quick Start

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/nepal-sbom-v2.git
cd nepal-sbom-v2

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file from the example:
```bash
cp .env.example .env
# Add your GROQ_API_KEY, GITHUB_CLIENT_ID, and GITHUB_CLIENT_SECRET
```

### 3. Run the Dashboard
```bash
python -m web.app
# Open http://localhost:8000 (Login: admin / nepal123)
```

### 4. CI/CD Integration
```bash
python cli/ci_scan.py --url http://localhost:8000 --username admin --password nepal123 --fail-on high --path .
```

---

## 📂 Project Structure
- `web/`: FastAPI app and API routes.
- `core/`: Scanner engine, AI remediation, and database logic.
- `templates/`: Professional HTML dashboard and history pages.
- `cli/`: Command-line interface for CI/CD automation.

---

## 🇳🇵 Built for secure development in South Asia.
MIT License © 2026 Nepal SBOM Scanner.
