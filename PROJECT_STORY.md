# 🇳🇵 Nepal SBOM Scanner: Project Journey

The **Nepal SBOM Scanner** is a professional, AI-powered Software Bill of Materials (SBOM) and security auditing platform designed for South Asian SaaS teams. It provides enterprise-grade security intelligence, automated remediation, and compliance-ready exports.

## 🚀 Core Features Built

### 1. Multi-Channel Repository Scanning
- **Local Uploads:** Drop ZIP archives for instant analysis.
- **Public GitHub:** Scan any open-source repository via URL.
- **Private GitHub Integration:** Secure OAuth-based access to private organizational repositories with a built-in repo explorer.

### 2. AI-Powered Security Intelligence
- **AI Remediation Engine:** Integrated with Groq LLM to provide 3-line targeted fixes (Threat, Fix, Verification) for every vulnerability.
- **AI Caching:** Efficient SQLite-based caching to reduce API costs and improve performance.
- **Executive Summary:** Generates jargon-free, CISO-level risk assessments and recommended action timelines.

### 3. Automated Remediation (PR Bot)
- **One-Click Fixes:** The "Auto-Fix PR" bot automatically clones a repository, creates a branch, applies dependency upgrades (using regex and JSON parsing), and opens a Pull Request on GitHub.

### 4. Deep Code Audit (SCA + SAST)
- **Secret Scanner:** Identifies hardcoded API keys, AWS credentials, and passwords across the codebase.
- **Code Security Auditor:** Scans for dangerous patterns like Command Injection (`os.system`), Insecure Deserialization (`pickle.load`), and risky JS patterns (`innerHTML`).

### 5. Compliance & Governance
- **SPDX 2.3 Export:** One-click download of compliance-ready SBOMs in standard JSON format.
- **Security Audit Log:** A historical record of all scans with security grades and detailed reports.
- **Security Grading:** Real-time project health assessment (A-F) based on vulnerability density.

### 6. DevOps & CI/CD Integration
- **CLI Scanner:** A production-ready Python tool (`cli/ci_scan.py`) that can be integrated into any CI pipeline to block builds if security risks are found.
- **GitHub Actions:** Pre-configured workflow templates for automated PR security gating.

---

## 🛠️ Technical Stack
- **Backend:** FastAPI (Python), Uvicorn, SQLite.
- **Frontend:** Vanilla JS, Tailwind CSS (Glassmorphism design), Lucide Icons, Google Fonts (Inter/Outfit).
- **AI:** Groq (Llama-3/Mixtral).
- **Security:** OSV.dev (Vulnerability Database), SPDX 2.3 standards.

---

## 🇳🇵 Built for the Future
This platform represents a complete security lifecycle: **Discovery -> Analysis -> Remediation -> Compliance**. It is ready for deployment and commercial use.
