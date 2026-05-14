import os
import sys
import json
import tempfile
import zipfile
import shutil
import subprocess
import time
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp

from fastapi import FastAPI, File, UploadFile, Form, Request, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.responses import Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.middleware.sessions import SessionMiddleware
import secrets
import httpx

from pydantic import BaseModel
from core.scanner import generate_report
from core.models import SbomReport
from core.database import init_db, save_scan, get_recent_scans, get_scan_by_id
from core.ai_explainer import get_remediation, get_executive_summary, get_structured_fix
from core.spdx_generator import generate_spdx

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")

app = FastAPI(
    title="Nepal SBOM Scanner",
    version=APP_VERSION,
    description="SBOM generation, OSV vulnerability intelligence, SPDX/CycloneDX export, and optional AI-assisted remediation.",
)
_https_only = os.environ.get("HTTPS_ONLY", "false").lower() in ("1", "true", "yes")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET_KEY", secrets.token_hex(32)),
    same_site="lax",
    https_only=_https_only,
)

security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username.encode("utf8"), os.environ.get("ADMIN_USERNAME", "admin").encode("utf8"))
    correct_password = secrets.compare_digest(credentials.password.encode("utf8"), os.environ.get("ADMIN_PASSWORD", "nepal123").encode("utf8"))
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Initialize database on startup
init_db()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "..", "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "..", "static")), name="static")

# Security configuration
MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
UPLOAD_RATE_LIMIT = int(os.environ.get("UPLOAD_RATE_LIMIT", "5"))  # per minute per IP
RATE_LIMIT_WINDOW = 60  # seconds

# In-memory rate limiter: {ip: [timestamp1, timestamp2, ...]}
_rate_limit_store = {}

def _check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    requests = _rate_limit_store.get(client_ip, [])
    # Filter to current window
    requests = [t for t in requests if t > window_start]
    _rate_limit_store[client_ip] = requests
    if len(requests) >= UPLOAD_RATE_LIMIT:
        return False
    requests.append(now)
    return True

def _is_valid_zip(file_path: str) -> bool:
    """Check magic bytes for ZIP file"""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            return header == b'PK\x03\x04' or header == b'PK\x05\x06' or header == b'PK\x07\x08'
    except Exception:
        return False

def _sanitize_filename(filename: str) -> str:
    """Prevent path traversal attacks"""
    return os.path.basename(filename.replace("\\", "/"))

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, username: str = Depends(get_current_username)):
    recent = get_recent_scans(10)
    return templates.TemplateResponse("index.html", {"request": request, "recent_scans": recent})

@app.post("/scan/upload")
async def scan_upload(request: Request, file: UploadFile = File(...), username: str = Depends(get_current_username)):
    client_ip = request.client.host
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded: max 5 uploads per minute")

    # Check file size via content length header if available
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Max size: {MAX_UPLOAD_SIZE // (1024*1024)}MB")

    temp_dir = tempfile.mkdtemp()
    try:
        safe_name = _sanitize_filename(file.filename)
        file_path = os.path.join(temp_dir, safe_name)

        # Stream write with size check
        size = 0
        with open(file_path, "wb") as f:
            while chunk := await file.read(8192):
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="File too large")
                f.write(chunk)

        # Validate ZIP magic bytes
        if safe_name.endswith('.zip'):
            if not _is_valid_zip(file_path):
                raise HTTPException(status_code=400, detail="Invalid ZIP file")
            extract_dir = os.path.join(temp_dir, "extracted")
            os.makedirs(extract_dir, exist_ok=True)
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Security: prevent zip slip (path traversal in zip entries)
                for member in zip_ref.namelist():
                    member_path = os.path.join(extract_dir, member)
                    if not os.path.commonpath([os.path.abspath(extract_dir)]) == os.path.commonpath([os.path.abspath(extract_dir), os.path.abspath(member_path)]):
                        raise HTTPException(status_code=400, detail="ZIP contains unsafe paths")
                zip_ref.extractall(extract_dir)
            scan_dir = extract_dir
        else:
            scan_dir = temp_dir

        report = await generate_report(scan_dir, safe_name)
        scan_id = save_scan(report)

        response_data = report.model_dump(mode='json')
        response_data["scan_id"] = scan_id
        return JSONResponse(content=response_data)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/scan/github")
async def scan_repo(repo_url: str = Form(...), username: str = Depends(get_current_username)):
    """Clone a public GitHub repo and scan it"""
    # Validate URL format (basic SSRF prevention)
    allowed_hosts = ("github.com", "www.github.com", "raw.githubusercontent.com")
    if not any(repo_url.startswith(f"https://{h}/") for h in allowed_hosts):
        raise HTTPException(status_code=400, detail="Only public GitHub repositories are supported")

    temp_dir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail=f"Git clone failed: {result.stderr}")

        project_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        report = await generate_report(temp_dir, project_name)
        scan_id = save_scan(report)

        response_data = report.model_dump(mode='json')
        response_data["scan_id"] = scan_id
        return JSONResponse(content=response_data)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Git clone timed out")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.get("/download/cyclonedx/{scan_id}")
async def download_cyclonedx(scan_id: int, username: str = Depends(get_current_username)):
    from core.database import get_scan_by_id
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_data = json.loads(scan["json_report"])
    packages = report_data.get("packages", [])

    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{scan_id}",
        "version": 1,
        "metadata": {
            "timestamp": scan["created_at"],
            "tools": [{"name": "Nepal SBOM Scanner", "version": APP_VERSION}]
        },
        "components": []
    }

    for pkg in packages:
        cyclonedx["components"].append({
            "type": "library",
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": pkg.get("purl", "")
        })

    return JSONResponse(content=cyclonedx)

class ExplainRequest(BaseModel):
    package_name: str
    version: str
    severity: str
    summary: str

@app.post("/explain/{cve_id}")
async def explain_vuln(cve_id: str, req: ExplainRequest, username: str = Depends(get_current_username)):
    explanation = await get_remediation(
        cve_id, req.package_name, req.version, req.severity, req.summary
    )
    return JSONResponse(content={"explanation": explanation})

@app.get("/executive-summary/{scan_id}")
async def executive_summary(scan_id: int, username: str = Depends(get_current_username)):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    report_data = json.loads(scan["json_report"])
    vulns = report_data.get("vulnerabilities", [])
    
    # We pass the vulnerabilities as a JSON string
    vulns_json = json.dumps(vulns)
    summary = await get_executive_summary(vulns_json)
    
    return JSONResponse(content={"summary": summary})

# --- Level 3: GitHub OAuth ---

GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

@app.get("/auth/github")
async def github_login(request: Request):
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub Client ID not configured")
    redirect_uri = str(request.url_for("github_callback"))
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={redirect_uri}&scope=repo,user"
    )

@app.get("/auth/github/callback")
async def github_callback(request: Request, code: str):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://github.com/login/oauth/access_token",
            params={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"},
        )
        data = resp.json()
        if "access_token" not in data:
            return JSONResponse(content={"error": "Failed to obtain token", "details": data}, status_code=400)
        
        request.session["github_token"] = data["access_token"]
    return RedirectResponse(url="/")

@app.get("/github/user")
async def get_github_user(request: Request):
    token = request.session.get("github_token")
    if not token:
        return JSONResponse(content={"authenticated": False})
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"}
        )
        if resp.status_code != 200:
            return JSONResponse(content={"authenticated": False})
        return JSONResponse(content={"authenticated": True, "user": resp.json()})

@app.get("/github/repos")
async def list_github_repos(request: Request):
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated with GitHub")
    
    async with httpx.AsyncClient() as client:
        # Fetch user's repos
        resp = await client.get(
            "https://api.github.com/user/repos?sort=updated&per_page=100",
            headers={"Authorization": f"token {token}"}
        )
        return JSONResponse(content=resp.json())

@app.post("/scan/github-private")
async def scan_private_repo(
    request: Request,
    repo_full_name: str = Form(...),
    username: str = Depends(get_current_username),
):
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated with GitHub")

    temp_dir = tempfile.mkdtemp()
    try:
        # Construct clone URL with token
        repo_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        if result.returncode != 0:
            # Mask token in error message
            error_msg = result.stderr.replace(token, "********")
            raise HTTPException(status_code=400, detail=f"Git clone failed: {error_msg}")

        project_name = repo_full_name.split("/")[-1]
        report = await generate_report(temp_dir, project_name)
        scan_id = save_scan(report)

        response_data = report.model_dump(mode='json')
        response_data["scan_id"] = scan_id
        return JSONResponse(content=response_data)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.post("/github/create-fix-pr")
async def create_fix_pr(
    request: Request,
    repo_full_name: str = Form(...),
    cve_id: str = Form(...),
    package_name: str = Form(...),
    current_version: str = Form(...),
    severity: str = Form(...),
    summary: str = Form(...),
    username: str = Depends(get_current_username),
):
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated with GitHub")

    # 1. Get structured fix from LLM
    fix = await get_structured_fix(cve_id, package_name, current_version, severity, summary)
    if not fix.get("version"):
        raise HTTPException(status_code=400, detail="LLM could not determine a safe target version")

    target_version = fix["version"]
    target_package = fix["package"]
    branch_name = f"fix/{target_package.lower()}-vuln-{cve_id.lower()}"

    temp_dir = tempfile.mkdtemp()
    try:
        # 2. Clone repo
        repo_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        subprocess.run(["git", "clone", "--depth", "1", repo_url, temp_dir], check=True)
        
        # 3. Create branch
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=temp_dir, check=True)

        # 4. Apply fix (Naive replacement for MVP)
        files_modified = []
        
        # Check requirements.txt
        req_path = os.path.join(temp_dir, "requirements.txt")
        if os.path.exists(req_path):
            with open(req_path, "r") as f:
                content = f.read()
            new_content = re.sub(
                rf"^{re.escape(target_package)}([<>=! ]+).*", 
                f"{target_package}=={target_version}", 
                content, 
                flags=re.MULTILINE | re.IGNORECASE
            )
            if new_content != content:
                with open(req_path, "w") as f:
                    f.write(new_content)
                files_modified.append("requirements.txt")

        # Check package.json
        pkg_path = os.path.join(temp_dir, "package.json")
        if os.path.exists(pkg_path):
            with open(pkg_path, "r") as f:
                data = json.load(f)
            
            modified = False
            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data and target_package in data[dep_type]:
                    data[dep_type][target_package] = f"^{target_version}" if "^" in data[dep_type][target_package] else target_version
                    modified = True
            
            if modified:
                with open(pkg_path, "w") as f:
                    json.dump(data, f, indent=2)
                files_modified.append("package.json")

        if not files_modified:
            raise HTTPException(status_code=400, detail=f"Could not find {target_package} in common dependency files")

        # 5. Commit and Push
        subprocess.run(["git", "config", "user.email", "bot@nepal-sbom.ai"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.name", "Nepal SBOM Bot"], cwd=temp_dir, check=True)
        subprocess.run(["git", "add", "."], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", f"fix({target_package}): resolve {cve_id} by upgrading to {target_version}"], cwd=temp_dir, check=True)
        subprocess.run(["git", "push", "origin", branch_name], cwd=temp_dir, check=True)

        # 6. Open Pull Request (base = repo default branch when available)
        default_branch = os.environ.get("DEFAULT_GIT_BRANCH", "main")
        async with httpx.AsyncClient(timeout=30.0) as client:
            meta = await client.get(
                f"https://api.github.com/repos/{repo_full_name}",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
            )
            if meta.status_code == 200:
                default_branch = meta.json().get("default_branch") or default_branch

            resp = await client.post(
                f"https://api.github.com/repos/{repo_full_name}/pulls",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json"
                },
                json={
                    "title": f"Security Fix: {target_package} upgrade to {target_version}",
                    "body": f"This automated PR fixes vulnerability **{cve_id}** ({severity} severity).\n\n**Description:** {summary}\n\n**Action taken:** Upgraded `{target_package}` from `{current_version}` to `{target_version}`.",
                    "head": branch_name,
                    "base": default_branch,
                }
            )
            pr_data = resp.json()
            if resp.status_code != 201:
                return JSONResponse(content={"error": "Branch pushed but failed to open PR", "details": pr_data}, status_code=500)
            
            return JSONResponse(content={"status": "success", "pr_url": pr_data.get("html_url")})

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.get("/history", response_class=HTMLResponse)
async def history(request: Request, username: str = Depends(get_current_username)):
    scans = get_recent_scans(limit=20)
    return templates.TemplateResponse("history.html", {"request": request, "scans": scans})

@app.get("/api/history")
async def api_history(username: str = Depends(get_current_username)):
    scans = get_recent_scans(limit=50)
    history_list = [
        {
            "id": s["id"],
            "project_name": s["project_name"],
            "timestamp": s["created_at"],
            "total_packages": s["total_packages"],
            "critical_count": s["critical_count"],
            "high_count": s["high_count"],
        }
        for s in scans
    ]
    return JSONResponse(content={"scans": history_list})

@app.get("/download/spdx/{scan_id}")
async def download_spdx(scan_id: int, username: str = Depends(get_current_username)):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_data = json.loads(scan["json_report"])
    spdx_json = generate_spdx(report_data)

    safe_project = "".join(
        c if c.isalnum() or c in "-._" else "_" for c in scan["project_name"]
    )[:64]
    created = scan.get("created_at") or "unknown"
    date_part = str(created).replace(" ", "T").split("T")[0]
    filename = f"sbom-{safe_project}-{date_part}.spdx.json"

    return Response(
        content=spdx_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/health")
async def health():
    checks = {
        "api": "ok",
        "database": "unknown",
        "osv_api": "unknown"
    }

    # Check database
    try:
        from core.database import get_connection
        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)}"

    # Check OSV API
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.osv.dev/v1/") as resp:
                checks["osv_api"] = "ok" if resp.status < 500 else f"status_{resp.status}"
    except Exception as e:
        checks["osv_api"] = f"error: {str(e)}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        content={"status": "healthy" if all_ok else "degraded", "checks": checks, "version": APP_VERSION},
        status_code=200 if all_ok else 503
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
