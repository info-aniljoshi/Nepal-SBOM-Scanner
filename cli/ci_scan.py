import os
import sys
import httpx
import tempfile
import zipfile
import argparse
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(description="Nepal SBOM Scanner CI/CD Tool")
    parser.add_argument("--url", required=True, help="Base URL of your Nepal SBOM Scanner (e.g. http://scanner.example.com)")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="high", help="Fail build if vulnerabilities of this severity or higher are found")
    parser.add_argument("--path", default=".", help="Path to project root to scan")
    
    args = parser.parse_args()

    print(f"[*] Preparing to scan project at {args.path}...")
    
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp_path = tmp.name
        
    try:
        with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(args.path):
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('node_modules', 'venv', '__pycache__')]
                for file in files:
                    if not file.startswith('.'):
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, args.path)
                        zipf.write(file_path, arcname)
        
        print("[*] Uploading to Nepal SBOM Scanner...")
        
        with open(tmp_path, 'rb') as f:
            # First perform a GET request to obtain the CSRF token (if applicable)
            client = httpx.Client(auth=(args.username, args.password))
            csrf_token = ""
            
            try:
                # Try to get CSRF token from a fast endpoint or index
                idx_response = client.get(f"{args.url.rstrip('/')}/")
                if "csrftoken" in client.cookies:
                    csrf_token = client.cookies["csrftoken"]
            except Exception:
                pass
            
            headers = {}
            if csrf_token:
                headers["X-CSRF-Token"] = csrf_token

            files_payload = {'file': (os.path.basename(args.path) + '.zip', f, 'application/zip')}
            response = client.post(
                f"{args.url.rstrip('/')}/scan/upload",
                files=files_payload,
                headers=headers,
                timeout=120.0
            )
        
        if response.status_code != 200:
            print(f"[X] Scan failed with status {response.status_code}: {response.text}")
            sys.exit(1)
            
        report = response.json()
        print(f"[OK] Scan complete! Found {report.get('total_packages', 0)} packages.")
        
        vulns = report.get("vulnerabilities", [])
        critical = report.get("critical_count", 0)
        high = report.get("high_count", 0)
        
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])
        
        print(f"[!] Results: {critical} Critical, {high} High, {medium} Medium, {low} Low")
        
        should_fail = False
        if args.fail_on == "critical" and critical > 0:
            should_fail = True
        elif args.fail_on == "high" and (critical > 0 or high > 0):
            should_fail = True
        elif args.fail_on == "medium" and (critical > 0 or high > 0 or medium > 0):
            should_fail = True
        elif args.fail_on == "low" and (critical > 0 or high > 0 or medium > 0 or low > 0):
            should_fail = True
            
        if should_fail:
            print(f"[!] Build failed due to vulnerabilities (Threshold: {args.fail_on})")
            sys.exit(1)
        else:
            print("[+] Build passed!")
            sys.exit(0)
            
    except Exception as e:
        print(f"[X] Error during scan: {e}")
        sys.exit(1)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == "__main__":
    main()
