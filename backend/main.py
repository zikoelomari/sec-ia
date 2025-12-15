from __future__ import annotations

import io
import json
import logging
import os
import sys
import time
import tempfile
import zipfile
import shutil
from collections import defaultdict, deque
from pathlib import Path
from typing import Literal, Optional, Tuple, List

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    canvas = None
    A4 = None

from .analyzers.bandit_analyzer import (
    analyze_python_code_with_bandit,
    analyze_python_path_with_bandit,
)
from .analyzers.multi_analyzer import (
    run_semgrep,
    run_snyk_code,
    run_eslint,
    run_codeql,
    check_binaries,
)
from .detectors.gemini_detector import detect_code_string, detect_path

try:
    from .generators.ai_code_generator import generate_code_with_ai, get_available_providers
    HAS_AI_GENERATOR = True
except ImportError:
    HAS_AI_GENERATOR = False
    generate_code_with_ai = None
    get_available_providers = None

try:
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse
    HAS_STATIC_FILES = True
except ImportError:
    HAS_STATIC_FILES = False
    StaticFiles = None
    FileResponse = None


LOG = logging.getLogger("sec-ia")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="AI Code Security Guardrail API")
# Ensure process and subprocesses use UTF-8 locale/encoding on startup (helps Windows subprocesses)
os.environ.setdefault("LANG", "en_US.UTF-8")
os.environ.setdefault("LC_ALL", "en_US.UTF-8")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# Restrict CORS to known frontends; allow overriding via env ALLOWED_ORIGINS (comma-separated)
default_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8501",  # Streamlit
    "http://localhost:8502",  # Streamlit (port unifié)
    "http://127.0.0.1:8501",
    "http://127.0.0.1:8502",
]
allowed_origins = [
    origin.strip()
    for origin in os.environ.get("ALLOWED_ORIGINS", ",".join(default_origins)).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Servir la landing page statique si disponible
static_dir = Path(__file__).parent.parent / "static"
if HAS_STATIC_FILES and static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    @app.get("/", response_class=FileResponse)
    async def serve_landing_page():
        """Sert la landing page HTML."""
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return {"message": "AI Code Security Guardrail API fonctionne"}
else:
    @app.get("/")
    async def root():
        """API root endpoint."""
        return {
            "message": "AI Code Security Guardrail API fonctionne",
            "docs": "/docs",
            "api_info": "/api",
            "frontend": "Utilisez l'interface Streamlit unifiée sur http://localhost:8501"
        }


# Allowed scanners
ALLOWED_SCANNERS = {"bandit", "semgrep", "snyk", "eslint", "codeql", "gemini_detector"}

# Optional report persistence
REPORTS_DIR = os.environ.get("REPORTS_DIR", "analyses")
SAVE_REPORTS = os.environ.get("SAVE_REPORTS", "0") == "1"


class AnalyzeRequest(BaseModel):
    language: Literal["python", "javascript", "typescript", "java", "csharp"]
    code: str
    # optional list of scanners to run, e.g. ["bandit","semgrep","snyk","eslint"]
    scanners: Optional[List[str]] = None


class AnalyzeRepoRequest(BaseModel):
    url: str  # https://github.com/OWNER/REPO ou .../tree/branch
    token: Optional[str] = None  # PAT pour dépôt privé (sinon None)
    scanners: Optional[List[str]] = None


class GenerateAndAnalyzeRequest(BaseModel):
    description: str
    language: Literal["python", "javascript", "typescript", "java", "csharp"]
    provider: Optional[Literal["openai", "anthropic", "simulate"]] = None
    model: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 500
    scanners: Optional[List[str]] = None


def suffix_for_language(language: str) -> str:
    """Retourne l'extension de fichier pour un langage."""
    mapping = {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "java": ".java",
        "csharp": ".cs",
    }
    return mapping.get(language.lower(), ".txt")


# Simple API key + in-memory rate limiter
# If `API_KEY` env var is set, requests must provide that key in the `X-API-KEY` header.
# RATE_LIMIT_PER_MIN controls allowed requests per minute per API key (default 60).
_API_KEY = os.environ.get("API_KEY")
_RATE_LIMIT = int(os.environ.get("RATE_LIMIT_PER_MIN", "60"))
# map api_key -> deque[timestamps]
_RATE_STATE: dict[str, deque] = defaultdict(lambda: deque())


def _ensure_rate(api_key: str) -> None:
    now = time.time()
    window_start = now - 60
    dq = _RATE_STATE[api_key]
    # drop old timestamps
    while dq and dq[0] < window_start:
        dq.popleft()
    # Opportunistic cleanup of stale keys to avoid unbounded growth
    if not dq:
        _RATE_STATE.pop(api_key, None)
        dq = _RATE_STATE[api_key]
    if len(_RATE_STATE) > 1000:
        for key in list(_RATE_STATE.keys()):
            if not _RATE_STATE[key]:
                _RATE_STATE.pop(key, None)
    if len(dq) >= _RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    dq.append(now)


async def get_api_key(request: Request, x_api_key: Optional[str] = Header(None)) -> str:
    """Dependency to validate API key and enforce rate limits.

    If `_API_KEY` is set in the environment, it is required in the `X-API-KEY` header.
    If not set, requests are allowed but are still tracked by a placeholder key 'anonymous'.
    """
    key = x_api_key
    if _API_KEY:
        if not key or key != _API_KEY:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key")
    else:
        # if no API key configured, use a per-client placeholder (IP-based) when possible
        if not key:
            # try to get remote addr
            client = request.client.host if request.client else "anonymous"
            key = f"anon:{client}"
    # enforce rate limit per key
    try:
        _ensure_rate(key)
    except HTTPException:
        raise
    return key


def maybe_persist_report(kind: str, payload: dict) -> None:
    """Persist reports when SAVE_REPORTS=1, best-effort to avoid impacting API responses."""
    if not SAVE_REPORTS:
        return
    try:
        ts = int(time.time())
        Path(REPORTS_DIR).mkdir(parents=True, exist_ok=True)
        fname = f"report_{kind}_{ts}.json"
        out = Path(REPORTS_DIR) / fname
        out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:  # pragma: no cover - best effort
        LOG.warning("Unable to persist report: %s", exc)


def parse_github_url(url: str) -> Tuple[str, str, Optional[str]]:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="URL GitHub invalide.")
    owner, repo = parts[0], parts[1]
    branch = parts[3] if len(parts) >= 4 and parts[2] == "tree" else None
    return owner, repo, branch


def download_repo_zip(owner: str, repo: str, branch: str, headers: dict) -> Path:
    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"

    # Limits: maximum download size (bytes) and maximum total extracted size
    MAX_ZIP_BYTES = int(os.environ.get("MAX_REPO_ZIP_BYTES", str(50 * 1024 * 1024)))
    MAX_EXTRACT_BYTES = int(os.environ.get("MAX_REPO_EXTRACT_BYTES", str(200 * 1024 * 1024)))

    # Stream the response to avoid loading large archives into memory
    resp = requests.get(zip_url, headers=headers, timeout=60, stream=True)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="Dépôt ou branche introuvable.")
    if resp.status_code == 403:
        raise HTTPException(status_code=403, detail="Accès refusé (token manquant ou rate-limit).")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail="Erreur lors du téléchargement du dépôt")

    # If server provides content-length, enforce it
    content_length = resp.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_ZIP_BYTES:
                raise HTTPException(status_code=413, detail="Archive trop volumineuse (Content-Length)")
        except ValueError:
            pass

    tmpdir = Path(tempfile.mkdtemp(prefix="repo_dl_"))
    tmp_zip = None
    try:
        # write streamed content to a temporary file while enforcing MAX_ZIP_BYTES
        tmp_zip_file = tempfile.NamedTemporaryFile(delete=False, prefix="repo_zip_", suffix=".zip")
        tmp_zip = Path(tmp_zip_file.name)
        total = 0
        for chunk in resp.iter_content(chunk_size=32 * 1024):
            if not chunk:
                continue
            total += len(chunk)
            if total > MAX_ZIP_BYTES:
                tmp_zip_file.close()
                raise HTTPException(status_code=413, detail="Archive trop volumineuse pendant le telechargement")
            tmp_zip_file.write(chunk)
        tmp_zip_file.flush()
        tmp_zip_file.close()

        # Open zip and perform safety checks before extracting
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            # compute total uncompressed size and guard against zip bombs
            total_uncompressed = 0
            for info in zf.infolist():
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_EXTRACT_BYTES:
                    raise HTTPException(status_code=413, detail="Archive contient trop de donnees extraites")

            # Safe extract: prevent path traversal
            def _is_within_directory(directory: Path, target: Path) -> bool:
                try:
                    return directory.resolve() in target.resolve().parents or directory.resolve() == target.resolve()
                except Exception:
                    return False

            for member in zf.infolist():
                member_path = tmpdir.joinpath(member.filename)
                if not _is_within_directory(tmpdir, member_path):
                    raise HTTPException(status_code=400, detail="Archive contient des chemins invalides")

            zf.extractall(tmpdir)
            root_name = zf.namelist()[0].split("/")[0]
            return tmpdir / root_name
    except Exception:
        # ensure cleanup on any failure
        try:
            if tmp_zip and tmp_zip.exists():
                tmp_zip.unlink()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    finally:
        # remove the temporary zip file if it still exists
        try:
            if tmp_zip and tmp_zip.exists():
                tmp_zip.unlink()
        except Exception:
            pass


def _normalize_and_validate_scanners(body_scanners: Optional[List[str]], query_scanners: Optional[str]) -> List[str]:
    """Return validated list of scanners from body or query param.

    Query param (comma-separated) takes precedence over body.
    Returns empty list to indicate default conservative selection.
    """
    raw: List[str] = []
    if query_scanners:
        # accept comma-separated values
        raw = [s.strip().lower() for s in query_scanners.split(",") if s.strip()]
    elif body_scanners:
        raw = [s.strip().lower() for s in body_scanners if isinstance(s, str) and s.strip()]

    if not raw:
        return []

    invalid = [s for s in raw if s not in ALLOWED_SCANNERS]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Scanner(s) non supporte(s): {invalid}. Choix valides: {sorted(ALLOWED_SCANNERS)}")
    return raw


def run_all_scans_on_path(target: Path, scanners: Optional[List[str]] = None, language: Optional[str] = None) -> dict:
    """Run selected scanners on `target` and measure per-scanner timings.

    If `scanners` is None or empty, this function will run a conservative default
    (Bandit + gemini_detector for Python, Semgrep + gemini_detector for other languages,
    and Bandit+Semgrep+gemini_detector when language is unknown). To run expensive scanners
    (semgrep/snyk/eslint), include them explicitly in the `scanners` list.
    """
    available = {"bandit", "semgrep", "snyk", "eslint", "codeql", "gemini_detector"}
    result: dict = {}
    sel = set([s.lower() for s in (scanners or []) if isinstance(s, str)])

    # default conservative selection
    if not sel:
        if language is None:
            sel = {"bandit", "semgrep", "gemini_detector"}
        elif isinstance(language, str) and language.lower() == "python":
            sel = {"bandit", "gemini_detector"}
        else:
            sel = {"semgrep", "gemini_detector"}

    # ensure we only run known scanners
    sel = sel & available

    # On Windows, Semgrep est désactivé par défaut (voir multi_analyzer.run_semgrep).
    # Si l'utilisateur veut forcer Semgrep, il peut définir FORCE_SEMGREP=1.
    if (sys.platform.startswith("win") or os.name == "nt") and os.environ.get("FORCE_SEMGREP", "0") != "1":
        sel.discard("semgrep")

    timings: dict = {}
    is_python = (language or "python").lower() == "python"

    if "bandit" in sel and is_python:
        start = time.time()
        result["bandit"] = analyze_python_path_with_bandit(target)
        timings["bandit"] = time.time() - start
    if "semgrep" in sel:
        start = time.time()
        result["semgrep"] = run_semgrep(target, language=language)
        timings["semgrep"] = time.time() - start
    if "snyk" in sel:
        start = time.time()
        result["snyk"] = run_snyk_code(target)
        timings["snyk"] = time.time() - start
    if "eslint" in sel:
        start = time.time()
        result["eslint"] = run_eslint(target)
        timings["eslint"] = time.time() - start
    if "codeql" in sel:
        start = time.time()
        result["codeql"] = run_codeql(target)
        timings["codeql"] = time.time() - start

    # gemini detector (fast, local)
    if "gemini_detector" in sel:
        start = time.time()
        result["gemini_detector"] = detect_path(target)
        timings["gemini_detector"] = time.time() - start

    result["_meta"] = {"timings": timings}
    LOG.info("Scanners executed: %s; timings: %s", list(sel), timings)
    return result


# Root endpoint géré par la landing page si disponible, sinon message JSON

@app.get("/api")
async def api_info() -> dict:
    """API information endpoint."""
    return {"message": "AI Code Security Guardrail API fonctionne"}


@app.get("/status")
async def status(api_key: str = Depends(get_api_key)) -> dict:
    """Return availability of scanner binaries and basic environment info.

    Useful for debugging CI/dev environments and for the frontend to decide
    which scans can be run locally.
    """
    bins = check_binaries()
    info = {
        "platform": {
            "os": os.name,
            "platform": sys.platform if hasattr(sys, "platform") else None,
        },
        "binaries": bins,
        "env": {"PYTHONUTF8": os.environ.get("PYTHONUTF8"), "PYTHONIOENCODING": os.environ.get("PYTHONIOENCODING")},
    }
    return info


@app.post("/analyze")
async def analyze(
    request: AnalyzeRequest,
    api_key: str = Depends(get_api_key),
    scanners: Optional[str] = Query(None, description="Comma-separated list of scanners to run"),
) -> dict:
    # Query param takes precedence over body
    sel = _normalize_and_validate_scanners(request.scanners, scanners)

    # pick file suffix based on language for better semgrep/eslint support
    suffix_map = {
        "python": ".py",
        "javascript": ".js",
        "typescript": ".ts",
        "java": ".java",
        "csharp": ".cs",
    }
    suffix = suffix_map.get(request.language, ".txt")

    LOG.info("Analyze snippet: scanners=%s", sel or ["bandit", "gemini_detector"])
    with tempfile.TemporaryDirectory(prefix="snippet_") as tmpdir:
        tmp_path = Path(tmpdir) / f"snippet{suffix}"
        tmp_path.write_text(request.code, encoding="utf-8")
        scans = run_all_scans_on_path(tmp_path, scanners=sel, language=request.language)
        # also run the in-memory detector for faster snippet feedback
        gemini = detect_code_string(request.code)
        scans["gemini_detector_snippet"] = gemini
        response = {"language": request.language, "scanners": scans}
        maybe_persist_report("snippet", response)
        return response


@app.post("/analyze-fast")
async def analyze_fast(request: AnalyzeRequest, api_key: str = Depends(get_api_key)) -> dict:
    """Faster, lightweight endpoint: run only Bandit (snippet) and the in-memory detector.

    Useful for quick developer feedback when a full scan (semgrep/snyk) is slow or unreliable.
    """
    if request.language != "python":
        return {"language": request.language, "error": "Langage non supporte"}

    LOG.info("Analyze-fast snippet triggered")
    bandit_result = analyze_python_code_with_bandit(request.code)
    gemini = detect_code_string(request.code)
    return {"language": "python", "scanners": {"bandit": bandit_result, "gemini_detector": gemini}}


@app.post("/analyze-github")
async def analyze_github(
    req: AnalyzeRepoRequest,
    api_key: str = Depends(get_api_key),
    scanners: Optional[str] = Query(None, description="Comma-separated list of scanners to run"),
) -> dict:
    owner, repo, branch = parse_github_url(req.url)

    # If branch not provided in URL, resolve default_branch via GitHub API
    token = req.token or os.environ.get("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "sec-ia"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if not branch:
        try:
            meta = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=10)
            if meta.status_code == 200:
                branch = meta.json().get("default_branch") or "main"
            else:
                branch = "main"
        except Exception:
            branch = "main"

    LOG.info("Analyze GitHub repo=%s/%s branch=%s scanners=%s", owner, repo, branch, req.scanners or scanners)
    repo_path = download_repo_zip(owner, repo, branch, headers)
    try:
        sel = _normalize_and_validate_scanners(req.scanners, scanners)
        scans = run_all_scans_on_path(repo_path, scanners=sel, language=None)
    finally:
        try:
            shutil.rmtree(repo_path.parent, ignore_errors=True)
        except Exception:
            pass

    response = {"language": "python", "repo": f"{owner}/{repo}@{branch}", "scanners": scans}
    maybe_persist_report("repo", response)
    return response


@app.get("/api/providers")
async def list_providers():
    """Liste des providers IA disponibles."""
    if not HAS_AI_GENERATOR:
        return {
            "available_providers": ["simulate"],
            "openai_configured": False,
            "anthropic_configured": False,
            "error": "AI generator module not available",
        }
    
    providers = get_available_providers()
    return {
        "available_providers": providers,
        "openai_configured": bool(os.environ.get("OPENAI_API_KEY")),
        "anthropic_configured": bool(os.environ.get("ANTHROPIC_API_KEY")),
    }


@app.post("/generate-and-analyze")
async def generate_and_analyze_endpoint(
    request: GenerateAndAnalyzeRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Génère du code via IA puis l'analyse immédiatement.
    
    Returns:
        - generation: résultat de la génération (code, model, tokens, cost)
        - analysis: résultats complets des scanners
    """
    if not HAS_AI_GENERATOR:
        raise HTTPException(
            status_code=503,
            detail="AI generator module not available. Install openai and anthropic packages."
        )
    
    LOG.info(f"Generate+Analyze: {request.description} ({request.language}, {request.provider})")
    
    # Étape 1 : Génération du code
    try:
        gen_result = await generate_code_with_ai(
            description=request.description,
            language=request.language,
            provider=request.provider,
            model=request.model,
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
    except Exception as e:
        LOG.error(f"Generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Code generation failed: {e}")
    
    # Étape 2 : Analyse du code généré
    code = gen_result["code"]
    
    # Déterminer les scanners à utiliser
    sel = set(request.scanners or [])
    if not sel:
        # Par défaut selon langage
        if request.language == "python":
            sel = {"bandit", "gemini_detector"}
        else:
            sel = {"semgrep", "gemini_detector"}
    
    sel = sel.intersection(ALLOWED_SCANNERS)
    
    # Sauvegarder temporairement pour analyse
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix_for_language(request.language),
        delete=False,
        encoding="utf-8"
    ) as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)
    
    try:
        scans = {}
        timings = {}
        
        # Bandit (Python only)
        if "bandit" in sel and request.language == "python":
            start = time.time()
            bandit_result = analyze_python_path_with_bandit(tmp_path)
            scans["bandit"] = bandit_result
            timings["bandit"] = time.time() - start
        
        # Semgrep (multi-language)
        if "semgrep" in sel:
            start = time.time()
            semgrep_result = run_semgrep(tmp_path, request.language)
            scans["semgrep"] = semgrep_result
            timings["semgrep"] = time.time() - start
        
        # Detector (fast, local)
        if "gemini_detector" in sel:
            start = time.time()
            detector_result = detect_code_string(code)
            scans["gemini_detector"] = detector_result
            timings["gemini_detector"] = time.time() - start
        
        return {
            "generation": {
                "code": code,
                "model": gen_result["model"],
                "provider": gen_result["provider"],
                "timestamp": gen_result["timestamp"],
                "tokens_used": gen_result["tokens_used"],
                "cost_usd": gen_result.get("cost_usd"),
                "metadata": gen_result["metadata"],
            },
            "analysis": {
                "language": request.language,
                "scanners": scans,
                "timings": timings,
            },
        }
    
    finally:
        # Cleanup
        if 'tmp_path' in locals() and tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


class ExportPdfRequest(BaseModel):
    language: Literal["python", "javascript", "typescript", "java", "csharp"]
    code: Optional[str] = None
    scanners: Optional[dict] = None
    summary: Optional[dict] = None


def generate_pdf_from_data(data: dict) -> bytes:
    """Generate a PDF report from analysis data."""
    if not HAS_REPORTLAB:
        raise HTTPException(status_code=503, detail="ReportLab n'est pas installé ; export PDF impossible.")
    
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 40
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Rapport de sécurité")
    y -= 30
    
    c.setFont("Helvetica", 12)
    
    # Language
    language = data.get("language", "unknown")
    c.drawString(40, y, f"Langage: {language}")
    y -= 18
    
    # Summary
    summary = data.get("summary", {})
    severity = summary.get("severity", {})
    if severity:
        c.drawString(40, y, "Sévérités:")
        y -= 18
        for level in ("HIGH", "MEDIUM", "LOW"):
            count = severity.get(level, 0)
            c.drawString(60, y, f"{level}: {count}")
            y -= 18
    
    risk_score = summary.get("risk_score", 0)
    c.drawString(40, y, f"Score de risque: {risk_score}")
    y -= 18
    
    # Scanners summary
    scanners = data.get("scanners", {})
    if scanners:
        c.drawString(40, y, "Scanners utilisés:")
        y -= 18
        for scanner_name in scanners.keys():
            if scanner_name != "_meta":
                c.drawString(60, y, f"- {scanner_name}")
                y -= 16
                if y < 60:
                    c.showPage()
                    y = height - 60
    
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer.getvalue()


@app.post("/export-pdf")
async def export_pdf(
    request: ExportPdfRequest,
    api_key: str = Depends(get_api_key),
) -> Response:
    """Export analysis results as PDF."""
    try:
        data = {
            "language": request.language,
            "code": request.code,
            "scanners": request.scanners or {},
            "summary": request.summary or {},
        }
        pdf_bytes = generate_pdf_from_data(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=security_report.pdf"}
        )
    except HTTPException:
        raise
    except Exception as e:
        LOG.error("Erreur génération PDF: %s", e)
        raise HTTPException(status_code=500, detail=f"Erreur lors de la génération du PDF: {str(e)}")
