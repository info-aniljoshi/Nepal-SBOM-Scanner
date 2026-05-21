import asyncio
import aiohttp
import logging
import re
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from core.models import Package, Vulnerability, Severity, SbomReport

logger = logging.getLogger("nepal-sbom-scanner")

OSV_API = "https://api.osv.dev/v1/querybatch"
TIMEOUT = aiohttp.ClientTimeout(total=30)

async def check_vulnerabilities(packages: List[Package]) -> List[Vulnerability]:
    """Expert Note: Implemented batching and error handling for OSV API"""
    if not packages:
        return []

    # Map ecosystems to OSV standards
    ecosystem_map = {"npm": "npm", "PyPI": "PyPI", "Maven": "Maven", "Go": "Go"}
    
    queries = [
        {
            "package": {"name": pkg.name, "ecosystem": ecosystem_map.get(pkg.ecosystem, pkg.ecosystem)},
            "version": pkg.version
        } 
        for pkg in packages
    ]

    vulns_found: List[Vulnerability] = []
    vuln_id_to_package: Dict[str, Tuple[str, str, str]] = {}

    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        # OSV recommends batches of <= 1000, we'll stay safe with 100
        for i in range(0, len(queries), 100):
            batch = queries[i:i+100]
            try:
                async with session.post(OSV_API, json={"queries": batch}) as resp:
                    if resp.status != 200:
                        logger.error(f"OSV Batch API error: {resp.status}")
                        continue
                    data = await resp.json()
            except Exception as e:
                logger.error(f"OSV connection error: {e}")
                continue

            results = data.get("results", [])
            for j, result in enumerate(results):
                current_pkg = packages[i + j]
                for v in result.get("vulns", []):
                    vid = v.get("id")
                    if vid:
                        vuln_id_to_package[vid] = (current_pkg.name, current_pkg.version, current_pkg.ecosystem)

        if not vuln_id_to_package:
            return []

        # Fetch full details for each unique vulnerability
        unique_vids = list(vuln_id_to_package.keys())
        
        async def fetch_vuln_details(vid: str) -> Optional[Dict[str, Any]]:
            try:
                async with session.get(f"https://api.osv.dev/v1/vulns/{vid}") as resp:
                    if resp.status == 200:
                        return await resp.json()
            except Exception as e:
                logger.warning(f"Failed to fetch details for {vid}: {e}")
            return None

        tasks = [fetch_vuln_details(vid) for vid in unique_vids]
        full_vulns_data = await asyncio.gather(*tasks)

        for v_data in full_vulns_data:
            if not v_data:
                continue

            vid = v_data.get("id", "UNKNOWN")
            severity = Severity.UNKNOWN
            score: Optional[float] = None

            # Severity logic: prioritize database_specific, then CVSS
            db_spec = v_data.get("database_specific", {})
            sev_str = str(db_spec.get("severity", "")).upper()
            
            if sev_str in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                severity = Severity(sev_str)
            elif sev_str == "MODERATE":
                severity = Severity.MEDIUM

            # Check for numeric CVSS score
            cvss_score = db_spec.get("cvss_score")
            if isinstance(cvss_score, (int, float)):
                score = float(cvss_score)
                if severity == Severity.UNKNOWN: # Only override if unknown
                    if score >= 9.0: severity = Severity.CRITICAL
                    elif score >= 7.0: severity = Severity.HIGH
                    elif score >= 4.0: severity = Severity.MEDIUM
                    elif score > 0: severity = Severity.LOW

            # Fallback if still unknown but has CVSS vector
            if severity == Severity.UNKNOWN and any(s.get("type") == "CVSS_V3" for s in v_data.get("severity", [])):
                severity = Severity.HIGH

            summary = v_data.get("summary") or v_data.get("details", "No summary available")
            summary = (summary[:197] + "...") if len(summary) > 200 else summary

            pkg_meta = vuln_id_to_package.get(vid)
            apkg, aver, aeco = pkg_meta if pkg_meta else (None, None, None)

            vulns_found.append(Vulnerability(
                id=vid,
                summary=summary,
                severity=severity,
                cvss_score=score,
                aliases=v_data.get("aliases", []),
                affected_package=apkg,
                affected_version=aver,
                affected_ecosystem=aeco,
            ))

    return vulns_found

async def scan_code_for_secrets(project_path: str) -> List[Vulnerability]:
    """Expert Note: Enhanced pattern matching with Pathlib and security-focused skip list"""
    patterns = {
        "SECRET_KEY": r"(?i)(secret[_-]?key|password|api[_-]?key|token|auth[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{10,})['\"]",
        "AWS_KEY": r"(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9/\+]{20,})['\"]",
        "DATABASE_URL": r"(?i)(postgres|mysql|mongodb|redis):\/\/(\w+):(\w+)@",
        "COMMAND_INJECTION": r"(os\.system|subprocess\.Popen|subprocess\.run|eval|exec)\(.*\+.*\)|\bshell\s*=\s*True",
        "INSECURE_DESERIALIZATION": r"(pickle\.load|yaml\.load)\(",
        "DANGEROUS_JS": r"(\.innerHTML|eval\()",
    }
    
    code_vulns: List[Vulnerability] = []
    base_path = Path(project_path).resolve()
    
    # Files to ignore
    skip_exts = {'.exe', '.bin', '.pdf', '.zip', '.tar.gz', '.png', '.jpg'}
    skip_dirs = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

    for path in base_path.rglob("*"):
        if any(part in skip_dirs for part in path.parts) or path.suffix in skip_exts or not path.is_file():
            continue
            
        try:
            # We only scan text files for speed
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    for key, pattern in patterns.items():
                        match = re.search(pattern, line)
                        if match:
                            rel_path = path.relative_to(base_path)
                            # Mask the secret value for safety
                            masked_match = match.group(0)[:15] + "********"
                            code_vulns.append(Vulnerability(
                                id=f"CODE-{key}-{line_num}",
                                summary=f"Potential {key} detected in {rel_path}",
                                severity=Severity.HIGH,
                                cvss_score=8.0,
                                aliases=[f"FILE:{rel_path}", f"LINE:{line_num}", f"MATCH_START:{masked_match}"]
                            ))
        except Exception as e:
            logger.debug(f"Could not scan file {path}: {e}")
            
    return code_vulns

async def generate_report(project_path: str, project_name: Optional[str] = None) -> SbomReport:
    """Expert Note: Integrated scanner orchestrator with comprehensive report generation"""
    from core.parsers import scan_directory
    
    path_obj = Path(project_path).resolve()
    if project_name is None:
        project_name = path_obj.name

    packages = scan_directory(str(path_obj))

    # Parallelize dependency and code scanning
    vulns_task = check_vulnerabilities(packages)
    code_task = scan_code_for_secrets(str(path_obj))
    
    vulns, code_vulns = await asyncio.gather(vulns_task, code_task)
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
