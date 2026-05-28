# 🛡️ Nepal SBOM Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)

**Nepal SBOM Scanner** is an enterprise-grade Supply Chain Security platform designed for teams that need deep visibility into their software dependencies. It combines automated SBOM generation, OSV-backed vulnerability intelligence, and AI-powered remediation into a single, sleek operator experience.

---

## ✨ Key Capabilities

| Feature | Description |
| :--- | :--- |
| **🔍 Multi-Source Scanning** | Support for ZIP uploads, public GitHub URLs, and private repositories via OAuth. |
| **🚨 OSV Intelligence** | Real-time vulnerability data from [OSV.dev](https://osv.dev/) with normalized severity grading. |
| **📦 Compliance Exports** | Generate industry-standard **SPDX 2.3** and **CycloneDX 1.5** JSON artifacts. |
| **🤖 AI Remediation** | Integrated AI (Groq/OpenAI) for executive summaries and structured upgrade paths. |
| **⚡ CI/CD Native** | Built-in CLI tools and GitHub Actions support for automated security gates. |
| **🛠️ Auto-Fix PRs** | Automated branch creation and Pull Requests for identified security vulnerabilities. |

---

## 🚀 Quick Start

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/your-username/nepal-sbom-scanner.git
cd nepal-sbom-scanner

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
```bash
cp .env.example .env
# Edit .env and set your ADMIN_PASSWORD and GROQ_API_KEY
```

### 3. Launch
```bash
python -m web.app
```
Access the dashboard at `http://localhost:8000` (Default: `admin` / `NepalScan_Secure_2026!@#`).

---

## 🛠️ Project Structure

```text
├── core/             # Parsers, OSV client, SPDX/CycloneDX generators
├── web/              # FastAPI routes and authentication logic
├── cli/              # CI/CD tools and local scanning scripts
├── templates/        # Modern, responsive dashboard UI
├── static/           # CSS, JS, and brand assets
└── examples/         # Sample vulnerable patterns for testing
```

---

## 🛡️ Security & Compliance
Nepal SBOM Scanner is built with security first. It includes:
- **HTTP Basic Auth** for dashboard access.
- **Secure File Handling** for ZIP processing.
- **Isolated Analysis** environments for repo cloning.

See [SECURITY.md](SECURITY.md) for more details.

---

## 🤝 Contributing
We welcome contributions! Please see our contributing guidelines for details on how to get started.

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
<p align="center">Made with ❤️ for the Security Community</p>

