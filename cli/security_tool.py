from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import textwrap
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

# Ajouter le backend au PYTHONPATH pour import
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from backend.generators.ai_code_generator import generate_code_with_ai, get_available_providers
    HAS_AI_GENERATOR = True
except ImportError:
    HAS_AI_GENERATOR = False
    generate_code_with_ai = None
    get_available_providers = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except Exception:  # pragma: no cover
    Console = None
    Panel = None
    Table = None

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover
    canvas = None
    A4 = None

console = Console() if Console else None

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".cs": "csharp",
}
LANG_SUFFIX = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "java": ".java",
    "csharp": ".cs",
}

JSONValue = str | int | float | bool | None | Dict[str, "JSONValue"] | List["JSONValue"]

PATTERN_REGEXES = {
    "assertions": re.compile(r"\bassert ", re.IGNORECASE),
    "subprocess": re.compile(r"subprocess|popen|shell=True", re.IGNORECASE),
    "exec": re.compile(r"exec\(", re.IGNORECASE),
    "secrets": re.compile(r"SECRET|TOKEN|PASSWORD|API_KEY", re.IGNORECASE),
    "injections": re.compile(r"(eval\(|os\.system|sql)", re.IGNORECASE),
}


def _print_info(message: str) -> None:
    """Display an informative message, optionally using rich."""
    if console:
        console.print(f"[bold cyan]{message}")
    else:
        print(message)


def _print_warning(message: str) -> None:
    """Display a warning message."""
    if console:
        console.print(f"[bold yellow]{message}")
    else:
        print(message)


def ensure_directory(path: Path) -> Path:
    """Create a directory if it does not exist and return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def suffix_for_language(language: str) -> str:
    """Return an extension for a given language (default .txt)."""
    return LANG_SUFFIX.get(language.lower(), ".txt")


def detect_language(path: Path, fallback: Optional[str] = None) -> str:
    """Infer language from file extension, falling back to the provided default."""
    if path.is_file():
        lang = SUPPORTED_EXTENSIONS.get(path.suffix.lower())
        if lang:
            return lang
    if fallback:
        return fallback.lower()
    return "python"


def load_prompts_file(path: Path) -> List[Dict[str, str]]:
    """Load a list of prompts from a .txt (one per ligne) ou .json ([\"...\"] ou [{\"description\":...,\"language\":...}])."""
    raw = path.read_text(encoding="utf-8")
    prompts: List[Dict[str, str]] = []
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Fichier JSON invalide: {exc}") from exc
        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, str) and entry.strip():
                    prompts.append({"description": entry.strip()})
                elif isinstance(entry, dict) and entry.get("description"):
                    prompts.append({"description": str(entry["description"]).strip(), "language": entry.get("language", "")})
        else:
            raise ValueError("Format JSON attendu: liste de chaines ou liste d'objets {description, language?}.")
    else:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                prompts.append({"description": line})
    if not prompts:
        raise ValueError("Aucun prompt valide dans le fichier fourni.")
    return prompts


def appel_au_modele_ia(description: str, language: str, seed: Optional[int] = None, run_index: int = 0) -> str:
    """Simulate an AI code generation call with probabilistic variability.
    
    Args:
        description: Description of the code to generate
        language: Target programming language
        seed: Optional seed for reproducibility
        run_index: Index of the run (0-based) for variability within same prompt
    """
    if seed is not None:
        rng = random.Random(seed + run_index)
    else:
        rng = random.Random()
    
    language_key = language.lower().strip()
    
    # Base templates with variations
    python_templates = [
        "def generated_function():\n"
        '    """Generated code for: {description}"""\n'
        '    print("Hello from generated code!")\n',
        "def generated_function():\n"
        '    """Generated code for: {description}"""\n'
        '    result = "Hello from generated code!"\n'
        '    return result\n',
        "def generated_function():\n"
        '    """Generated code for: {description}"""\n'
        '    message = "Hello from generated code!"\n'
        '    print(message)\n',
    ]
    
    js_templates = [
        "function generatedFunction() {\n"
        "    // Generated code for: {description}\n"
        "    console.log('Hello from generated code!');\n"
        "}\n",
        "const generatedFunction = () => {\n"
        "    // Generated code for: {description}\n"
        "    console.log('Hello from generated code!');\n"
        "};\n",
        "function generatedFunction() {\n"
        "    // Generated code for: {description}\n"
        "    const msg = 'Hello from generated code!';\n"
        "    console.log(msg);\n"
        "}\n",
    ]
    
    java_templates = [
        "public class GeneratedClass {\n"
        "    public static void run() {\n"
        '        System.out.println("Generated code for: {description}");\n'
        "    }\n"
        "}\n",
        "public class GeneratedClass {\n"
        "    public static void main(String[] args) {\n"
        '        System.out.println("Generated code for: {description}");\n'
        "    }\n"
        "}\n",
    ]
    
    csharp_templates = [
        "using System;\n"
        "public static class GeneratedClass {\n"
        "    public static void Run() {\n"
        '        Console.WriteLine("Generated code for: {description}");\n'
        "    }\n"
        "}\n",
        "using System;\n"
        "public class GeneratedClass {\n"
        "    public static void Main() {\n"
        '        Console.WriteLine("Generated code for: {description}");\n'
        "    }\n"
        "}\n",
    ]
    
    template_map = {
        "python": python_templates,
        "javascript": js_templates,
        "typescript": js_templates,
        "java": java_templates,
        "csharp": csharp_templates,
    }
    
    templates = template_map.get(language_key, [])
    if templates:
        template = rng.choice(templates)
    else:
        template = f"// Generated code for: {description} (language {language})\n"
    
    # Add some random variations (comments, spacing, variable names)
    if rng.random() > 0.5:
        # Add extra comment
        if language_key == "python":
            template = f'# Additional comment for run {run_index}\n{template}'
        else:
            template = f'// Additional comment for run {run_index}\n{template}'
    
    return template.format(description=description)


def capture_generation_metadata(description: str, language: str, file_path: Path) -> Dict[str, JSONValue]:
    """Collect metadata for a generated snippet."""
    content = file_path.read_bytes()
    return {
        "description": description,
        "language": language,
        "model": "simulated",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "file_path": str(file_path),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def run_bandit(path: Path) -> Optional[Dict[str, JSONValue]]:
    """Execute Bandit on the provided path (Python only) and return the parsed JSON."""
    language = detect_language(path)
    if language != "python":
        return None
    target = path.resolve()
    if not target.exists():
        raise FileNotFoundError(f"Le chemin {target} est introuvable.")

    base_cmd = ["bandit", "-f", "json"]
    cmd = base_cmd + (["-r", str(target)] if target.is_dir() else [str(target)])

    _print_info(f"[+] Execution de Bandit sur {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        _print_warning("Bandit n'est pas installe ; rapport indisponible.")
        return None

    if result.returncode not in (0, 1):
        _print_warning(f"Bandit a echoue: {result.stderr.strip() or 'erreur inconnue'}")
        return None

    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        _print_warning("Impossible de parser la sortie JSON de Bandit.")
        return None


def run_semgrep(path: Path) -> Optional[Dict[str, JSONValue]]:
    """Execute Semgrep on the provided path and return parsed JSON."""
    target = str(path)
    cmd = ["semgrep", "--json", "--config", "auto", target]
    _print_info(f"[+] Execution de Semgrep sur {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        _print_warning("Semgrep n'est pas installe ; rapport indisponible.")
        return None

    if result.returncode not in (0, 1):
        _print_warning(f"Semgrep a echoue: {result.stderr.strip() or 'erreur inconnue'}")
        return None

    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        _print_warning("Impossible de parser la sortie JSON de Semgrep.")
        return None


def run_snyk(path: Path) -> Optional[Dict[str, JSONValue]]:
    """Execute Snyk Code on the provided path and return parsed JSON."""
    target = str(path)
    cmd: List[str] = ["snyk", "code", "test", "--json"]
    if path.is_file():
        cmd += ["--file", target]
    else:
        cmd.append(target)

    _print_info(f"[+] Execution de Snyk sur {target}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        _print_warning("Snyk n'est pas installe ; rapport indisponible.")
        return None

    if result.returncode not in (0, 1):
        _print_warning(f"Snyk a echoue: {result.stderr.strip() or 'erreur inconnue'}")
        return None

    try:
        return json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        _print_warning("Impossible de parser la sortie JSON de Snyk.")
        return None


def summarize_bandit(bandit_data: Optional[Dict[str, JSONValue]]) -> Dict[str, int]:
    """Aggregate Bandit severities into a dict."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    if not bandit_data:
        return counts
    for issue in bandit_data.get("results", []):
        severity = (issue.get("issue_severity") or "").upper()
        if severity in counts:
            counts[severity] += 1
    return counts


def calculate_risk_score(severity: Dict[str, int]) -> float:
    """Compute a risk score based on severity counts."""
    weights = {"HIGH": 5, "MEDIUM": 2, "LOW": 1}
    return float(sum(weights[key] * severity.get(key, 0) for key in weights))


def detect_dangerous_patterns(path: Path) -> Dict[str, int]:
    """Scan files for predefined risky patterns."""
    counts = {name: 0 for name in PATTERN_REGEXES}
    if path.is_file():
        targets: Iterable[Path] = [path]
    else:
        targets = [
            file_path
            for file_path in path.rglob("*")
            if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_EXTENSIONS
        ]

    for file_path in targets:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, regex in PATTERN_REGEXES.items():
            if regex.search(text):
                counts[name] += 1
    return counts


def build_summary(
    metadata: Dict[str, JSONValue],
    bandit_data: Optional[Dict[str, JSONValue]],
    semgrep_data: Optional[Dict[str, JSONValue]],
    snyk_data: Optional[Dict[str, JSONValue]],
    patterns: Dict[str, int],
) -> Dict[str, JSONValue]:
    """Assemble the summary section of a report bundle."""
    severity = summarize_bandit(bandit_data)
    summary = {
        "metadata": metadata,
        "severity": severity,
        "risk_score": calculate_risk_score(severity),
        "patterns": patterns,
        "semgrep_findings": semgrep_data.get("results", []) if semgrep_data else [],
        "snyk_findings": snyk_data.get("issues", []) if snyk_data else [],
    }
    return summary


def save_report_bundle(bundle: Dict[str, JSONValue], token: str) -> Path:
    """Persist the combined report to analyses/report_<token>.json."""
    analyses_dir = ensure_directory(Path("analyses"))
    output_path = analyses_dir / f"report_{token}.json"
    output_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    return output_path


def load_report_bundle(path: Path) -> Dict[str, JSONValue]:
    """Load a saved bundle from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def build_github_headers() -> Dict[str, str]:
    """Return HTTP headers for GitHub API calls."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "security-tool/1.0",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_github_url(github_url: str) -> Tuple[str, str, Optional[str]]:
    """Extract owner, repo and optional branch from a GitHub URL."""
    parsed = urlparse(github_url)
    parts = [segment for segment in parsed.path.strip("/").split("/") if segment]
    if len(parts) < 2:
        raise ValueError("URL GitHub invalide. Format attendu: https://github.com/OWNER/REPO")
    owner, repo = parts[0], parts[1]
    branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = parts[3]
    return owner, repo, branch


def _github_request(
    url: str, headers: Dict[str, str], params: Optional[Dict[str, JSONValue]] = None
) -> requests.Response:
    """Wrapper around requests.get with consistent error handling."""
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
    except requests.RequestException as exc:
        raise RuntimeError(f"Echec de la requete GitHub: {exc}") from exc
    return response


def resolve_branch(owner: str, repo: str, branch_hint: Optional[str], headers: Dict[str, str]) -> str:
    """Determine which branch to use when downloading files via the GitHub API."""
    if branch_hint:
        return branch_hint

    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = _github_request(repo_url, headers)
    if resp.status_code == 200:
        default_branch = resp.json().get("default_branch")
        if default_branch:
            return default_branch

    for fallback in ("main", "master", "dev"):
        branch_resp = _github_request(f"{repo_url}/branches/{fallback}", headers)
        if branch_resp.status_code == 200:
            return fallback

    return "main"


def normalize_extensions(raw: Optional[Iterable[str]]) -> Set[str]:
    """Normalize a list of extensions (.py, py, etc.) into a set."""
    if not raw:
        return set(SUPPORTED_EXTENSIONS.keys())
    normalized: Set[str] = set()
    for ext in raw:
        value = ext.strip()
        if not value:
            continue
        if not value.startswith("."):
            value = f".{value}"
        normalized.add(value.lower())
    return normalized or set(SUPPORTED_EXTENSIONS.keys())


def api_github_list_files_recursive(
    owner: str,
    repo: str,
    branch: str,
    headers: Dict[str, str],
    extensions: Optional[Set[str]] = None,
) -> List[Dict[str, JSONValue]]:
    """List repository files by walking the contents API with pagination."""
    target_extensions = extensions or set(SUPPORTED_EXTENSIONS.keys())
    files: List[Dict[str, JSONValue]] = []

    def walk(path: str) -> None:
        page = 1
        while True:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents"
            if path:
                url = f"{url}/{path}"
            resp = _github_request(
                url,
                headers,
                params={"ref": branch, "per_page": 100, "page": page},
            )
            if resp.status_code == 404:
                raise RuntimeError(f"Chemin introuvable dans le depot: {path or '/'}")
            if resp.status_code == 403:
                raise RuntimeError(f"Acces refuse par l'API GitHub: {resp.text}")
            if resp.status_code != 200:
                raise RuntimeError(f"Erreur API GitHub ({resp.status_code}): {resp.text}")

            entries = resp.json()
            if isinstance(entries, dict):
                entries = [entries]
            if not entries:
                break

            for entry in entries:
                entry_type = entry.get("type")
                entry_path = entry.get("path", "")
                if entry_type == "file":
                    if Path(entry_path).suffix.lower() in target_extensions:
                        files.append(entry)
                elif entry_type == "dir":
                    walk(entry_path)

            if "next" not in resp.links:
                break
            page += 1

    walk("")
    return files


def telecharger_fichier(
    owner: str, repo: str, branch: str, path_in_repo: str, headers: Dict[str, str], dest_dir: Path
) -> None:
    """Download a file via the GitHub API and write it locally."""
    content_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_in_repo}"
    resp = _github_request(content_url, headers, params={"ref": branch})
    if resp.status_code != 200:
        raise RuntimeError(f"Echec du telechargement de {path_in_repo}: {resp.text}")
    payload = resp.json()
    if payload.get("encoding") != "base64":
        raise RuntimeError(f"Encodage inattendu pour {path_in_repo}: {payload.get('encoding')}")
    decoded = base64.b64decode(payload.get("content", "").encode("utf-8"))
    destination = dest_dir / path_in_repo
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(decoded)


def telecharger_repo_via_github_api(
    github_url: str,
    dest_dir: Path,
    branch_override: Optional[str] = None,
    extensions: Optional[Iterable[str]] = None,
) -> str:
    """Download supported files from a GitHub repository using the REST API."""
    owner, repo, branch_hint = parse_github_url(github_url)
    headers = build_github_headers()
    ensure_directory(dest_dir)

    branch = resolve_branch(owner, repo, branch_override or branch_hint, headers)
    ext_filter = normalize_extensions(extensions)
    file_entries = api_github_list_files_recursive(owner, repo, branch, headers, ext_filter)

    if not file_entries:
        raise RuntimeError("Aucun fichier correspondant aux extensions cibles.")

    for entry in file_entries:
        relative_path = entry.get("path", "")
        _print_info(f"[+] Telechargement de {relative_path} ({branch})")
        telecharger_fichier(owner, repo, branch, relative_path, headers, dest_dir)
    return branch


def run_security_suite(target: Path, metadata: Dict[str, JSONValue]) -> Dict[str, JSONValue]:
    """Execute all scanners and return an aggregated bundle."""
    bandit_report = run_bandit(target)
    semgrep_report = run_semgrep(target)
    snyk_report = run_snyk(target)
    pattern_counts = detect_dangerous_patterns(target)
    summary = build_summary(metadata, bandit_report, semgrep_report, snyk_report, pattern_counts)
    return {
        "metadata": metadata,
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "scans": {
            "bandit": bandit_report,
            "semgrep": semgrep_report,
            "snyk": snyk_report,
        },
        "summary": summary,
    }


def cmd_campaign(args: argparse.Namespace) -> None:
    """Lancer une campagne multi-prompts et agréger les métriques de risque."""
    prompts = load_prompts_file(Path(args.prompts))
    campaign_id = args.name or dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    gen_dir = ensure_directory(Path("generated_code") / f"campaign_{campaign_id}")
    analyses_dir = ensure_directory(Path("analyses"))
    
    runs_per_prompt = getattr(args, "runs_per_prompt", 3)
    if runs_per_prompt < 1:
        runs_per_prompt = 1
    elif runs_per_prompt > 5:
        runs_per_prompt = 5
    
    seed = getattr(args, "seed", None)
    if seed is not None:
        random.seed(seed)

    totals = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    risk_scores: List[float] = []
    cases: List[Dict[str, JSONValue]] = []

    for idx, prompt in enumerate(prompts, start=1):
        desc = prompt.get("description", "").strip()
        if not desc:
            continue
        lang = (prompt.get("language") or args.language or "python").lower()
        suffix = suffix_for_language(lang)
        
        prompt_cases = []
        
        # Generate multiple runs per prompt
        for run_idx in range(runs_per_prompt):
            filename = f"{idx:02d}_run{run_idx+1}_{lang}{suffix}"
            file_path = gen_dir / filename

            # Utiliser les vraies API si disponibles
            provider = getattr(args, "provider", None)
            code, gen_metadata = generate_ai_code(
                desc, lang, provider=provider, run_index=run_idx
            )
            file_path.write_text(code, encoding="utf-8")
            _print_info(f"[{idx}/{len(prompts)}] Run {run_idx+1}/{runs_per_prompt} - Code généré dans {file_path}")

            metadata = {
                "description": desc,
                "language": lang,
                "timestamp": dt.datetime.utcnow().isoformat() + "Z",
                "campaign": campaign_id,
                "type": "campaign_prompt",
                "path": str(file_path),
                "prompt_id": prompt.get("id", f"prompt_{idx}"),
                "run_index": run_idx,
                "runs_per_prompt": runs_per_prompt,
            }
            metadata.update(gen_metadata)  # Fusionner les métadonnées de génération
            bundle = run_security_suite(file_path, metadata)
            token = f"campaign_{campaign_id}_{idx:02d}_run{run_idx+1}"
            report_path = save_report_bundle(bundle, token)
            severity = bundle.get("summary", {}).get("severity", {}) or {}
            risk_score = bundle.get("summary", {}).get("risk_score", 0) or 0
            for level in totals:
                totals[level] += int(severity.get(level, 0) or 0)
            risk_scores.append(float(risk_score))
            
            prompt_cases.append(
                {
                    "run_index": run_idx,
                    "report": str(report_path),
                    "severity": severity,
                    "risk_score": risk_score,
                }
            )

        cases.append(
            {
                "prompt": desc,
                "prompt_id": prompt.get("id", f"prompt_{idx}"),
                "language": lang,
                "runs": prompt_cases,
            }
        )

    aggregated = {
        "campaign_id": campaign_id,
        "created_at": dt.datetime.utcnow().isoformat() + "Z",
        "prompts_file": str(Path(args.prompts).resolve()),
        "default_language": args.language,
        "runs_per_prompt": runs_per_prompt,
        "seed": seed,
        "totals": totals,
        "risk_score_avg": (sum(risk_scores) / len(risk_scores)) if risk_scores else 0.0,
        "risk_score_std": (
            (sum((x - (sum(risk_scores) / len(risk_scores))) ** 2 for x in risk_scores) / len(risk_scores)) ** 0.5
            if risk_scores and len(risk_scores) > 1
            else 0.0
        ),
        "cases": cases,
    }
    agg_path = analyses_dir / f"campaign_{campaign_id}.json"
    agg_path.write_text(json.dumps(aggregated, indent=2), encoding="utf-8")
    _print_info(
        f"[+] Campagne terminée. Totaux HIGH={totals['HIGH']}, MEDIUM={totals['MEDIUM']}, "
        f"LOW={totals['LOW']} | rapport agrégé: {agg_path}"
    )


def clone_repo(url: str, base_dir: Path) -> Tuple[Path, str]:
    """Clone a repository and return its local path and identifier."""
    repo_id = uuid.uuid4().hex[:8]
    repo_dir = base_dir / f"repo_{repo_id}"
    repo_dir.mkdir(parents=True, exist_ok=True)

    _print_info(f"[+] Clonage du depot {url} dans {repo_dir} ...")
    try:
        subprocess.run(["git", "clone", url, str(repo_dir)], check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("Git n'est pas installe.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Echec du clonage: {exc}") from exc

    return repo_dir, repo_id


def persist_and_report(bundle: Dict[str, JSONValue], token: str) -> None:
    """Persist a bundle and print a CLI-friendly summary."""
    report_path = save_report_bundle(bundle, token)
    severity = bundle["summary"].get("severity", {})
    _print_info(
        "Résumé: "
        + f"HIGH={severity.get('HIGH', 0)}, MEDIUM={severity.get('MEDIUM', 0)}, LOW={severity.get('LOW', 0)}"
    )
    _print_info(f"Score de risque: {bundle['summary'].get('risk_score', 0)}")
    _print_info(f"[+] Rapport enregistre dans {report_path}")


def generate_ai_code(
    description: str,
    language: str,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    run_index: int = 0
) -> Tuple[str, Dict[str, JSONValue]]:
    """
    Génère du code via API IA réelle avec fallback sur simulation.
    
    Args:
        description: Description du code à générer
        language: Langage cible
        provider: "openai" | "anthropic" | "simulate" | None (auto-detect)
        model: Modèle spécifique ou None
        run_index: Index de l'exécution (pour campagnes)
    
    Returns:
        (code_généré, metadata)
    """
    # Essayer d'utiliser les vraies API si disponibles
    if HAS_AI_GENERATOR:
        try:
            available = get_available_providers()
            _print_info(f"[*] Providers disponibles: {', '.join(available)}")
            
            # Utiliser asyncio pour appeler la fonction async
            result = asyncio.run(generate_code_with_ai(
                description=description,
                language=language,
                provider=provider,
                model=model
            ))
            
            code = result["code"]
            metadata = {
                "description": description,
                "language": language,
                "model": result["model"],
                "provider": result["provider"],
                "timestamp": result["timestamp"],
                "tokens_used": result["tokens_used"],
                "cost_usd": result.get("cost_usd", 0.0),
                "run_index": run_index,
            }
            
            _print_info(f"[✓] Code généré avec {result['provider']} ({result['model']})")
            _print_info(f"    Tokens: {result['tokens_used']}, Coût: ${result.get('cost_usd', 0):.4f}")
            
            return code, metadata
            
        except Exception as e:
            _print_warning(f"[!] Erreur lors de la génération IA: {e}")
            _print_warning("[!] Fallback sur génération simulée")
    
    # Fallback sur simulation
    code = appel_au_modele_ia(description, language, run_index=run_index)
    metadata = {
        "description": description,
        "language": language,
        "provider": "simulate",
        "model": "simulated-template-v1",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "tokens_used": len(code) // 4,  # Approximation
        "cost_usd": 0.0,
        "run_index": run_index,
    }
    return code, metadata


def cmd_generate(args: argparse.Namespace) -> None:
    """Handle the generate sub-command."""
    generated_dir = ensure_directory(Path("generated_code"))
    language = (args.language or "python").lower()
    suffix = {
        "python": ".py",
        "javascript": ".js",
        "java": ".java",
        "csharp": ".cs",
    }.get(language, ".txt")
    filename = args.output or f"{uuid.uuid4().hex[:8]}{suffix}"
    file_path = generated_dir / filename

    code, gen_metadata = generate_ai_code(
        args.description,
        language,
        provider=getattr(args, "provider", None),
        model=getattr(args, "model", None)
    )
    file_path.write_text(code, encoding="utf-8")
    _print_info(f"[+] Code genere ecrit dans {file_path}")

    metadata = capture_generation_metadata(args.description, language, file_path)
    metadata.update(gen_metadata)  # Fusionner les métadonnées de génération
    bundle = run_security_suite(file_path, metadata)
    persist_and_report(bundle, Path(filename).stem)


def cmd_analyse_repo(args: argparse.Namespace) -> None:
    """Handle the analyse-repo sub-command."""
    base_dir = ensure_directory(Path("repos_clones"))
    try:
        repo_dir, repo_id = clone_repo(args.url, base_dir)
    except RuntimeError as exc:
        _print_warning(f"[!] {exc}")
        sys.exit(1)

    metadata = {
        "source": args.url,
        "language": "mixed",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "type": "repo_clone",
        "path": str(repo_dir),
    }
    bundle = run_security_suite(repo_dir, metadata)
    persist_and_report(bundle, f"repo_{repo_id}")


def cmd_analyse_github_api(args: argparse.Namespace) -> None:
    """Handle the analyse-github-api sub-command using the GitHub REST API."""
    base_dir = ensure_directory(Path("repos_clones"))
    repo_id = uuid.uuid4().hex[:8]
    destination = base_dir / f"repo_api_{repo_id}"

    extensions = None
    if getattr(args, "extensions", None):
        extensions = [part.strip() for part in args.extensions.split(",")]

    try:
        branch_used = telecharger_repo_via_github_api(
            args.url,
            destination,
            branch_override=getattr(args, "branch", None),
            extensions=extensions,
        )
    except (RuntimeError, ValueError) as exc:
        _print_warning(f"[!] {exc}")
        sys.exit(1)

    metadata = {
        "source": args.url,
        "language": "mixed",
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "type": "repo_api",
        "path": str(destination),
        "branch": branch_used,
    }
    bundle = run_security_suite(destination, metadata)
    persist_and_report(bundle, f"repo_api_{repo_id}")


def cmd_compare_ia_vs_oss(args: argparse.Namespace) -> None:
    """Compare two existing JSON reports."""
    ia_report = load_report_bundle(Path(args.ia_report))
    oss_report = load_report_bundle(Path(args.oss_report))
    ia_summary = ia_report.get("summary", {})
    oss_summary = oss_report.get("summary", {})

    def fmt(summary: Dict[str, JSONValue]) -> str:
        sev = summary.get("severity", {})
        return f"HIGH={sev.get('HIGH',0)}, MEDIUM={sev.get('MEDIUM',0)}, LOW={sev.get('LOW',0)}"

    _print_info("=== Comparaison IA vs OSS ===")
    _print_info(f"IA : {fmt(ia_summary)} | Score={ia_summary.get('risk_score')}")
    _print_info(f"OSS: {fmt(oss_summary)} | Score={oss_summary.get('risk_score')}")
    delta = (ia_summary.get("risk_score", 0) or 0) - (oss_summary.get("risk_score", 0) or 0)
    if delta > 0:
        _print_warning(f"Le code IA presente un risque +{delta} par rapport a l'OSS.")
    elif delta < 0:
        _print_info(f"Le code IA presente un risque {delta} par rapport a l'OSS.")
    else:
        _print_info("Risque equivalent entre IA et OSS.")


def generate_pdf_report(report: Dict[str, JSONValue], output_path: Path) -> None:
    """Generate a PDF summary for a given report."""
    if not canvas or not A4:
        raise RuntimeError("ReportLab n'est pas installe ; export PDF impossible.")

    c = canvas.Canvas(str(output_path), pagesize=A4)
    width, height = A4
    y = height - 40

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, y, "Rapport de securite")
    y -= 30

    c.setFont("Helvetica", 12)
    metadata = report.get("metadata", {})
    for key in ("description", "language", "source", "timestamp"):
        if key in metadata:
            c.drawString(40, y, f"{key.capitalize()}: {metadata[key]}")
            y -= 18

    severity = report.get("summary", {}).get("severity", {})
    c.drawString(40, y, "Severites:")
    y -= 18
    for level in ("HIGH", "MEDIUM", "LOW"):
        c.drawString(60, y, f"{level}: {severity.get(level, 0)}")
        y -= 18

    c.drawString(40, y, f"Score de risque: {report.get('summary', {}).get('risk_score', 0)}")
    y -= 18

    c.drawString(40, y, "Patterns detectes:")
    y -= 18
    patterns = report.get("summary", {}).get("patterns", {})
    for name, count in patterns.items():
        c.drawString(60, y, f"{name}: {count}")
        y -= 16
        if y < 60:
            c.showPage()
            y = height - 60

    c.showPage()
    c.save()


def cmd_export_pdf(args: argparse.Namespace) -> None:
    """Export a JSON report as a PDF file."""
    report = load_report_bundle(Path(args.report))
    output = Path(args.output) if args.output else Path(args.report).with_suffix(".pdf")
    generate_pdf_report(report, output)
    _print_info(f"[+] Rapport PDF ecrit dans {output}")


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""
    parser = argparse.ArgumentParser(description="Generation de code et analyse multi-scanners.")
    subparsers = parser.add_subparsers(dest="command")

    p_generate = subparsers.add_parser("generate", help="Generer du code IA et lancer les scanners.")
    p_generate.add_argument("-d", "--description", required=True, help="Description du code a generer.")
    p_generate.add_argument("-l", "--language", default="python", help="Langage cible (python, javascript, ...).")
    p_generate.add_argument("-o", "--output", help="Nom de fichier de sortie.")
    p_generate.add_argument("--provider", choices=["openai", "anthropic", "simulate"], 
                           help="AI provider (auto-detect if not specified)")
    p_generate.add_argument("--model", help="Specific model name")
    p_generate.add_argument("--temperature", type=float, default=0.7, 
                           help="Generation temperature (0.0-1.0)")
    p_generate.set_defaults(func=cmd_generate)

    p_campaign = subparsers.add_parser(
        "campaign",
        help="Lancer une campagne multi-prompts et agréger les métriques dans analyses/.",
    )
    p_campaign.add_argument("-p", "--prompts", required=True, help="Fichier .txt ou .json listant les prompts.")
    p_campaign.add_argument(
        "-l",
        "--language",
        default="python",
        help="Langage par défaut pour les prompts (surchargé si un prompt précise un langage).",
    )
    p_campaign.add_argument(
        "-n",
        "--name",
        help="Identifiant de campagne (sinon timestamp).",
    )
    p_campaign.add_argument(
        "--runs-per-prompt",
        type=int,
        default=3,
        help="Nombre de générations par prompt (3-5, défaut: 3).",
    )
    p_campaign.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed aléatoire pour reproductibilité (optionnel).",
    )
    p_campaign.add_argument(
        "--provider",
        choices=["openai", "anthropic", "simulate"],
        help="AI provider pour la campagne (auto-detect si non spécifié).",
    )
    p_campaign.add_argument(
        "--model",
        help="Modèle spécifique pour la génération.",
    )
    p_campaign.set_defaults(func=cmd_campaign)

    p_repo = subparsers.add_parser("analyse-repo", help="Cloner un depot et lancer les scanners.")
    p_repo.add_argument("url", help="URL du depot GitHub a analyser.")
    p_repo.set_defaults(func=cmd_analyse_repo)

    p_repo_api = subparsers.add_parser(
        "analyse-github-api",
        help="Analyser un depot via l'API GitHub sans git clone.",
    )
    p_repo_api.add_argument("url", help="URL GitHub de reference.")
    p_repo_api.add_argument(
        "--branch",
        help="Nom de branche a forcer (sinon auto-detection).",
    )
    p_repo_api.add_argument(
        "--extensions",
        help="Liste d'extensions a recuperer (ex: .py,.js,.java).",
    )
    p_repo_api.set_defaults(func=cmd_analyse_github_api)

    p_compare = subparsers.add_parser("compare", help="Comparer deux rapports (IA vs OSS).")
    p_compare.add_argument("ia_report", help="Rapport JSON provenant de generate.")
    p_compare.add_argument("oss_report", help="Rapport JSON provenant d'un repo open-source.")
    p_compare.set_defaults(func=cmd_compare_ia_vs_oss)

    p_pdf = subparsers.add_parser("export-pdf", help="Generer un PDF a partir d'un rapport JSON.")
    p_pdf.add_argument("report", help="Chemin vers le rapport JSON.")
    p_pdf.add_argument("-o", "--output", help="Nom de fichier PDF de sortie.")
    p_pdf.set_defaults(func=cmd_export_pdf)

    return parser


def main() -> None:
    """Entrypoint for the CLI tool."""
    parser = build_parser()
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    try:
        args.func(args)
    except Exception as exc:
        _print_warning(f"[!] Erreur: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
