import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
from starlette_csrf import CSRFMiddleware

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.ai_explainer import get_executive_summary, get_remediation, get_structured_fix
from core.database import get_recent_scans, get_scan_by_id, init_db, save_scan
from core.scanner import generate_report
from core.spdx_generator import generate_spdx

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("nepal-sbom-web")

APP_VERSION = os.environ.get("APP_VERSION", "1.0.0")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Nepal SBOM Scanner",
    version=APP_VERSION,
    description="SBOM generation, OSV vulnerability intelligence, SPDX/CycloneDX export, and optional AI-assisted remediation.",
    lifespan=lifespan,
)

_https_only = os.environ.get("HTTPS_ONLY", "false").lower() in ("1", "true", "yes")
_session_secret = os.environ.get("SESSION_SECRET_KEY", secrets.token_hex(32))

app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret,
    same_site="lax",
    https_only=_https_only,
)

# CSRF token must be readable by JS (double-submit) for fetch(); httponly=False is the library default.
app.add_middleware(
    CSRFMiddleware,
    secret=_session_secret,
    header_name="X-CSRF-Token",
    cookie_name="csrftoken",
    cookie_httponly=False,
    cookie_secure=_https_only,
    cookie_samesite="lax",
)

security = HTTPBasic()


def get_current_username(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    admin_user = os.environ.get("ADMIN_USERNAME", "admin")
    admin_pass = os.environ.get("ADMIN_PASSWORD", "NepalScan_Secure_2026!@#")

    is_correct_username = secrets.compare_digest(
        credentials.username.encode("utf8"), admin_user.encode("utf8")
    )
    is_correct_password = secrets.compare_digest(
        credentials.password.encode("utf8"), admin_pass.encode("utf8")
    )

    if not (is_correct_username and is_correct_password):
        logger.warning("Failed login attempt for user: %s", credentials.username)
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR.parent / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR.parent / "static")), name="static")

MAX_UPLOAD_SIZE = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "50")) * 1024 * 1024
UPLOAD_RATE_LIMIT = int(os.environ.get("UPLOAD_RATE_LIMIT", "5"))
RATE_LIMIT_WINDOW = 60

_rate_limit_store: Dict[str, List[float]] = {}
_rate_limit_lock = threading.Lock()


def _check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    with _rate_limit_lock:
        reqs = _rate_limit_store.get(client_ip, [])
        reqs = [t for t in reqs if t > window_start]
        if len(reqs) >= UPLOAD_RATE_LIMIT:
            return False
        reqs.append(now)
        _rate_limit_store[client_ip] = reqs
        return True


def _is_valid_zip(file_path: Path) -> bool:
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            return header in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
    except OSError:
        return False


def _sanitize_filename(filename: str) -> str:
    safe_name = os.path.basename(filename.replace("\\", "/"))
    return re.sub(r"[^a-zA-Z0-9.\-_]", "_", safe_name)


_GH_OWNER_REPO = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
_GH_RESERVED_OWNERS = frozenset(
    {
        "apps",
        "explore",
        "features",
        "login",
        "marketplace",
        "orgs",
        "security",
        "settings",
        "sponsors",
        "topics",
    }
)


def _normalize_public_github_repo(raw: str) -> Optional[Tuple[str, str, str]]:
    """
    Turn a pasted public GitHub URL (or git@ clone string) into:
    (https clone URL ending in .git, owner/repo for PR flows, short repo name).

    Accepts e.g. https://github.com/o/r, .../o/r/tree/main, http://..., git@github.com:o/r.git
    Only github.com (including www.) — not GitHub Enterprise Server hosts.
    """
    s = (raw or "").strip()
    if not s:
        return None

    if s.startswith("git@github.com:"):
        rest = s[len("git@github.com:") :].strip()
        if rest.endswith(".git"):
            rest = rest[:-4]
        parts = [p for p in rest.split("/") if p]
        if len(parts) < 2:
            return None
        owner, repo = parts[0], parts[1]
        if owner in _GH_RESERVED_OWNERS or not _GH_OWNER_REPO.match(owner) or not _GH_OWNER_REPO.match(repo):
            return None
        clone = f"https://github.com/{owner}/{repo}.git"
        return clone, f"{owner}/{repo}", repo

    if not re.match(r"^https?://", s, re.IGNORECASE):
        return None

    parsed = urlparse(s)
    host = (parsed.hostname or "").lower()
    if host == "www.github.com":
        host = "github.com"
    if host != "github.com":
        return None

    segments = [seg for seg in parsed.path.strip("/").split("/") if seg]
    if len(segments) < 2:
        return None

    owner, repo = segments[0], segments[1]
    if owner in _GH_RESERVED_OWNERS:
        return None
    if not _GH_OWNER_REPO.match(owner) or not _GH_OWNER_REPO.match(repo):
        return None

    repo_clean = repo[:-4] if repo.endswith(".git") else repo
    clone = f"https://github.com/{owner}/{repo_clean}.git"
    return clone, f"{owner}/{repo_clean}", repo_clean


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if isinstance(exc, HTTPException):
        detail = exc.detail
        if not isinstance(detail, str):
            detail = str(detail)
        return JSONResponse(status_code=exc.status_code, content={"detail": detail})
    logger.exception("Unhandled error: %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again later."},
    )


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, username: str = Depends(get_current_username)) -> Response:
    recent = get_recent_scans(10)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "recent_scans": recent, "app_version": APP_VERSION},
    )


@app.post("/scan/upload")
async def scan_upload(
    request: Request,
    file: UploadFile = File(...),
    username: str = Depends(get_current_username),
) -> JSONResponse:
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_UPLOAD_SIZE:
                raise HTTPException(status_code=413, detail="File too large")
        except ValueError:
            pass

    temp_dir = Path(tempfile.mkdtemp())
    try:
        safe_name = _sanitize_filename(file.filename or "upload.zip")
        file_path = temp_dir / safe_name

        size = 0
        with open(file_path, "wb") as f:
            while chunk := await file.read(8192):
                size += len(chunk)
                if size > MAX_UPLOAD_SIZE:
                    raise HTTPException(status_code=413, detail="File too large")
                f.write(chunk)

        if safe_name.endswith(".zip"):
            if not _is_valid_zip(file_path):
                raise HTTPException(status_code=400, detail="Invalid ZIP file")

            extract_dir = temp_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)

            with zipfile.ZipFile(file_path, "r") as zip_ref:
                for member in zip_ref.namelist():
                    member_path = (extract_dir / member).resolve()
                    if not member_path.is_relative_to(extract_dir.resolve()):
                        raise HTTPException(status_code=400, detail="ZIP contains unsafe paths")
                zip_ref.extractall(extract_dir)
            scan_dir = extract_dir
        else:
            scan_dir = temp_dir

        report = await generate_report(str(scan_dir), safe_name)
        scan_id = save_scan(report)

        response_data = report.model_dump(mode="json")
        response_data["scan_id"] = scan_id
        return JSONResponse(content=response_data)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/scan/github")
async def scan_repo(
    repo_url: str = Form(...),
    username: str = Depends(get_current_username),
) -> JSONResponse:
    normalized = _normalize_public_github_repo(repo_url)
    if not normalized:
        raise HTTPException(
            status_code=400,
            detail="Invalid repository URL. Paste a public github.com repo link (HTTPS, http, or git@github.com:owner/repo).",
        )

    clone_url, github_full_name, project_name = normalized

    temp_dir = Path(tempfile.mkdtemp())
    try:
        clone_cmd = [
            "git",
            "-c",
            "core.protectNTFS=false",
            "-c",
            "core.longpaths=true",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            clone_url,
            str(temp_dir),
        ]

        result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=180)

        if result.returncode != 0:
            has_files = any(f.is_file() for f in temp_dir.iterdir() if f.name != ".git")
            if not has_files:
                logger.error("Clone failed: %s", result.stderr)
                raise HTTPException(status_code=400, detail="Repository could not be cloned")

        report = await generate_report(str(temp_dir), project_name)
        scan_id = save_scan(report)

        response_data = report.model_dump(mode="json")
        response_data["scan_id"] = scan_id
        response_data["github_full_name"] = github_full_name
        return JSONResponse(content=response_data)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Clone timed out")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/download/cyclonedx/{scan_id}")
async def download_cyclonedx(
    scan_id: int, username: str = Depends(get_current_username)
) -> Response:
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
            "tools": [{"name": "Nepal SBOM Scanner", "version": APP_VERSION}],
        },
        "components": [
            {
                "type": "library",
                "name": pkg["name"],
                "version": pkg["version"],
                "purl": pkg.get("purl", ""),
            }
            for pkg in packages
        ],
    }
    body = json.dumps(cyclonedx, indent=2)
    filename = f"sbom-{scan['project_name']}.cdx.json"
    return Response(
        content=body,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class ExplainRequest(BaseModel):
    package_name: str
    version: str
    severity: str
    summary: str


@app.post("/explain/{cve_id}")
async def explain_vuln(
    cve_id: str,
    req: ExplainRequest,
    username: str = Depends(get_current_username),
) -> JSONResponse:
    explanation = await get_remediation(
        cve_id, req.package_name, req.version, req.severity, req.summary
    )
    return JSONResponse(content={"explanation": explanation})


@app.get("/executive-summary/{scan_id}")
async def executive_summary_route(
    scan_id: int, username: str = Depends(get_current_username)
) -> JSONResponse:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_data = json.loads(scan["json_report"])
    vulns = report_data.get("vulnerabilities", [])
    summary = await get_executive_summary(json.dumps(vulns))
    return JSONResponse(content={"summary": summary})


GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")


@app.get("/auth/github")
async def github_login(request: Request) -> RedirectResponse:
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")
    redirect_uri = str(request.url_for("github_callback"))
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={redirect_uri}&scope=repo,user"
    )


@app.get("/auth/github/callback")
async def github_callback(request: Request, code: str) -> Response:
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
            return JSONResponse(content={"error": "Auth failed"}, status_code=400)

        request.session["github_token"] = data["access_token"]
    return RedirectResponse(url="/")


@app.get("/github/user")
async def get_github_user(request: Request) -> JSONResponse:
    token = request.session.get("github_token")
    if not token:
        return JSONResponse(content={"authenticated": False})

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}"},
        )
        return JSONResponse(
            content={
                "authenticated": resp.status_code == 200,
                "user": resp.json() if resp.status_code == 200 else None,
            }
        )


@app.get("/github/repos")
async def list_github_repos(request: Request) -> JSONResponse:
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401)

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user/repos?sort=updated&per_page=100",
            headers={"Authorization": f"token {token}"},
        )
        return JSONResponse(content=resp.json())


@app.post("/scan/github-private")
async def scan_private_repo(
    request: Request,
    repo_full_name: str = Form(...),
    username: str = Depends(get_current_username),
) -> JSONResponse:
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401)

    temp_dir = Path(tempfile.mkdtemp())
    try:
        repo_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(temp_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            logger.error("Private clone failed for %s", repo_full_name)
            raise HTTPException(status_code=400, detail="Clone failed")

        report = await generate_report(str(temp_dir), repo_full_name.split("/")[-1])
        scan_id = save_scan(report)
        return JSONResponse(content={"scan_id": scan_id, **report.model_dump(mode="json")})
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
) -> JSONResponse:
    token = request.session.get("github_token")
    if not token:
        raise HTTPException(status_code=401)

    fix = await get_structured_fix(cve_id, package_name, current_version, severity, summary)
    if not fix.get("version"):
        raise HTTPException(status_code=400, detail="Fix could not be generated")

    target_version = fix["version"]
    target_package = fix["package"]
    branch_name = f"fix/{target_package.lower()}-vuln-{cve_id.lower()}"

    temp_dir = Path(tempfile.mkdtemp())
    try:
        repo_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
        subprocess.run(["git", "clone", "--depth", "1", repo_url, str(temp_dir)], check=True)
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=temp_dir, check=True)

        modified = False
        req_file = temp_dir / "requirements.txt"
        if req_file.exists():
            content = req_file.read_text()
            new_content = re.sub(
                rf"^{re.escape(target_package)}([<>=! ]+).*",
                f"{target_package}=={target_version}",
                content,
                flags=re.MULTILINE | re.IGNORECASE,
            )
            if new_content != content:
                req_file.write_text(new_content)
                modified = True

        pkg_file = temp_dir / "package.json"
        if pkg_file.exists():
            data = json.loads(pkg_file.read_text())
            for dep_type in ["dependencies", "devDependencies"]:
                if dep_type in data and target_package in data[dep_type]:
                    data[dep_type][target_package] = (
                        f"^{target_version}"
                        if "^" in str(data[dep_type][target_package])
                        else target_version
                    )
                    modified = True
            if modified:
                pkg_file.write_text(json.dumps(data, indent=2))

        if not modified:
            raise HTTPException(status_code=400, detail="Package not found in dependency files")

        subprocess.run(
            ["git", "config", "user.email", "bot@nepal-sbom.ai"],
            cwd=temp_dir,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Nepal SBOM Bot"],
            cwd=temp_dir,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=temp_dir, check=True)
        subprocess.run(
            ["git", "commit", "-m", f"fix({target_package}): resolve {cve_id}"],
            cwd=temp_dir,
            check=True,
        )
        subprocess.run(["git", "push", "origin", branch_name], cwd=temp_dir, check=True)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"https://api.github.com/repos/{repo_full_name}/pulls",
                headers={
                    "Authorization": f"token {token}",
                    "Accept": "application/vnd.github.v3+json",
                },
                json={
                    "title": f"Security Fix: {target_package} upgrade to {target_version}",
                    "body": f"Automated security upgrade to resolve {cve_id}.\n\n{summary}",
                    "head": branch_name,
                    "base": "main",
                },
            )
            body: Any = {}
            try:
                body = resp.json()
            except Exception:
                body = {"message": resp.text}

            if 200 <= resp.status_code < 300 and isinstance(body, dict) and body.get("html_url"):
                return JSONResponse(
                    status_code=201,
                    content={
                        "status": "success",
                        "pr_url": body["html_url"],
                        "number": body.get("number"),
                    },
                )
            err_msg = (
                body.get("message")
                if isinstance(body, dict)
                else str(body)
            )
            if isinstance(body, dict) and body.get("errors"):
                err_msg = str(body["errors"][0]) if body["errors"] else err_msg
            return JSONResponse(
                status_code=resp.status_code if resp.status_code >= 400 else 400,
                content={"status": "error", "error": err_msg or "Pull request failed"},
            )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request, username: str = Depends(get_current_username)) -> Response:
    scans = get_recent_scans(limit=20)
    return templates.TemplateResponse("history.html", {"request": request, "scans": scans})


@app.get("/api/history")
async def api_history_route(username: str = Depends(get_current_username)) -> JSONResponse:
    scans = get_recent_scans(limit=50)
    return JSONResponse(content={"scans": scans})


@app.get("/download/spdx/{scan_id}")
async def download_spdx_route(
    scan_id: int, username: str = Depends(get_current_username)
) -> Response:
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404)

    spdx_json = generate_spdx(json.loads(scan["json_report"]))
    filename = f"sbom-{scan['project_name']}.spdx.json"
    return Response(
        content=spdx_json,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/health")
async def health_check() -> JSONResponse:
    checks: Dict[str, str] = {"api": "ok", "database": "unknown", "osv_api": "unknown"}
    try:
        from core.database import get_connection

        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {e!s}"

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get("https://api.osv.dev/v1/", timeout=5.0)
            checks["osv_api"] = "ok" if resp.status_code < 500 else "degraded"
        except Exception:
            checks["osv_api"] = "down"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        content={"status": "healthy" if all_ok else "degraded", "checks": checks},
        status_code=200 if all_ok else 503,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
