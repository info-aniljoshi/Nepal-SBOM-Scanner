import asyncio
import aiohttp
from typing import List
from core.models import Package, Vulnerability, Severity, SbomReport

OSV_API = "https://api.osv.dev/v1/querybatch"

async def check_vulnerabilities(packages: List[Package]) -> List[Vulnerability]:
    if not packages:
        return []

    queries = []
    for pkg in packages:
        ecosystem_map = {
            "npm": "npm",
            "PyPI": "PyPI",
            "Maven": "Maven",
            "Go": "Go",
        }
        eco = ecosystem_map.get(pkg.ecosystem, pkg.ecosystem)
        queries.append({
            "package": {
                "name": pkg.name,
                "ecosystem": eco,
            },
            "version": pkg.version,
        })

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(OSV_API, json={"queries": queries[:100]}) as resp:
                data = await resp.json()
        except Exception as e:
            print(f"OSV API error: {e}")
            return []

    vuln_ids = set()
    results = data.get("results", [])
    # OSV returns one result object per query, in the same order as `queries`
    vuln_id_to_package = {}
    for i, result in enumerate(results):
        if i >= len(packages):
            break
        pkg = packages[i]
        for v in result.get("vulns", []):
            vid = v.get("id")
            if not vid:
                continue
            vuln_ids.add(vid)
            vuln_id_to_package.setdefault(
                vid,
                (pkg.name, pkg.version, pkg.ecosystem),
            )

    vulns = []
    if not vuln_ids:
        return vulns

    async def fetch_vuln(session, vid):
        try:
            async with session.get(f"https://api.osv.dev/v1/vulns/{vid}") as resp:
                if resp.status == 200:
                    return await resp.json()
        except Exception:
            pass
        return None

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_vuln(session, vid) for vid in vuln_ids]
        full_vulns = await asyncio.gather(*tasks)

    for v in full_vulns:
        if not v:
            continue

        severity = Severity.UNKNOWN
        score = None

        # 1. Try database_specific.severity (most reliable for OSV)
        db = v.get("database_specific", {})
        if "severity" in db:
            sev_str = db["severity"].upper()
            if sev_str in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                severity = Severity(sev_str)
            elif sev_str == "MODERATE":
                severity = Severity.MEDIUM

        # 2. Try CVSS v3 score from severity array
        for s in v.get("severity", []):
            if s.get("type") == "CVSS_V3":
                pass

        # 3. Check for numeric cvss score in database_specific
        if "cvss_score" in db and isinstance(db["cvss_score"], (int, float)):
            score = float(db["cvss_score"])
            if score >= 9.0:
                severity = Severity.CRITICAL
            elif score >= 7.0:
                severity = Severity.HIGH
            elif score >= 4.0:
                severity = Severity.MEDIUM
            elif score > 0:
                severity = Severity.LOW

        # 4. Fallback: if no severity found but CVSS vector exists, default to HIGH
        if severity == Severity.UNKNOWN and any(s.get("type") == "CVSS_V3" for s in v.get("severity", [])):
            severity = Severity.HIGH

        # Summary fallback: use details if summary is missing
        summary = v.get("summary") or v.get("details", "No summary available")
        if len(summary) > 200:
            summary = summary[:197] + "..."

        vid = v.get("id", "UNKNOWN")
        pkg_meta = vuln_id_to_package.get(vid)
        apkg, aver, aeco = (None, None, None)
        if pkg_meta:
            apkg, aver, aeco = pkg_meta

        vulns.append(Vulnerability(
            id=vid,
            summary=summary,
            severity=severity,
            cvss_score=score,
            aliases=v.get("aliases", []),
            affected_package=apkg,
            affected_version=aver,
            affected_ecosystem=aeco,
        ))

    return vulns

async def scan_code_for_secrets(project_path: str) -> List[Vulnerability]:
    """Scans source code files for hardcoded secrets and security flaws"""
    import os
    import re

    patterns = {
        "SECRET_KEY": r"(?i)(secret[_-]?key|password|api[_-]?key|token|auth[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{10,})['\"]",
        "AWS_KEY": r"(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9/\+]{20,})['\"]",
        "DATABASE_URL": r"(?i)(postgres|mysql|mongodb|redis):\/\/(\w+):(\w+)@",
        "COMMAND_INJECTION": r"(os\.system|subprocess\.Popen|subprocess\.run|eval|exec)\(.*\+.*\)|\bshell\s*=\s*True",
        "INSECURE_DESERIALIZATION": r"(pickle\.load|yaml\.load)\(",
        "DANGEROUS_JS": r"(\.innerHTML|eval\()",
    }
    
    code_vulns = []
    
    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'venv', '__pycache__')]
        for file in files:
            if file.endswith(('.py', '.js', '.ts', '.env', '.json', '.yml', '.yaml', '.conf')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for line_num, line in enumerate(lines, 1):
                            for key, pattern in patterns.items():
                                match = re.search(pattern, line)
                                if match:
                                    rel_path = os.path.relpath(file_path, project_path)
                                    code_vulns.append(Vulnerability(
                                        id=f"CODE-{key}-{line_num}",
                                        summary=f"Hardcoded {key} found in {rel_path} at line {line_num}",
                                        severity=Severity.HIGH,
                                        cvss_score=8.0,
                                        aliases=[f"FILE:{rel_path}", f"LINE:{line_num}", f"MATCH:{match.group(0)[:15]}..."]
                                    ))
                except:
                    continue
    return code_vulns

async def generate_report(project_path: str, project_name: str = None) -> SbomReport:
    import os
    from core.parsers import scan_directory

    if project_name is None:
        project_name = os.path.basename(os.path.abspath(project_path))

    packages = scan_directory(project_path)

    # 1. Dependency Vulnerabilities (OSV)
    vulns = await check_vulnerabilities(packages)
    
    # 2. Source Code Vulnerabilities (Secrets/Patterns)
    code_vulns = await scan_code_for_secrets(project_path)
    vulns.extend(code_vulns)

    critical = sum(1 for v in vulns if v.severity == Severity.CRITICAL)
    high = sum(1 for v in vulns if v.severity == Severity.HIGH)

    return SbomReport(
        project_name=project_name,
        packages=packages,
        vulnerabilities=vulns,
        total_packages=len(packages),
        critical_count=critical,
        high_count=high,
    )
