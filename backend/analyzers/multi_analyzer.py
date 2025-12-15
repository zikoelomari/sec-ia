from __future__ import annotations

import json
import os
import subprocess
import shutil
import sys
import platform
from pathlib import Path
from typing import Dict, List, Optional, TypedDict

# Allow operators to tune scanner execution caps (seconds) without code changes.
DEFAULT_TIMEOUT = int(os.environ.get("SCANNER_TIMEOUT_SECONDS", "120"))
# Allow per-language Semgrep configs via env (e.g. SEMGREP_CONFIG_JS=p/ci)
SEMGREP_CONFIG_DEFAULT = os.environ.get("SEMGREP_CONFIG_DEFAULT", "auto")
SEMGREP_CONFIG_PY = os.environ.get("SEMGREP_CONFIG_PY", SEMGREP_CONFIG_DEFAULT)
SEMGREP_CONFIG_JS = os.environ.get("SEMGREP_CONFIG_JS", SEMGREP_CONFIG_DEFAULT)
SEMGREP_CONFIG_TS = os.environ.get("SEMGREP_CONFIG_TS", SEMGREP_CONFIG_DEFAULT)
SEMGREP_CONFIG_JAVA = os.environ.get("SEMGREP_CONFIG_JAVA", SEMGREP_CONFIG_DEFAULT)
SEMGREP_CONFIG_CS = os.environ.get("SEMGREP_CONFIG_CS", SEMGREP_CONFIG_DEFAULT)

JSONValue = str | int | float | bool | None | Dict[str, "JSONValue"] | List["JSONValue"]


class BinaryInfo(TypedDict, total=False):
    available: bool
    version: Optional[str]
    error: Optional[str]


class SemgrepIssue(TypedDict, total=False):
    path: Optional[str]
    start: Optional[int]
    end: Optional[int]
    check_id: Optional[str]
    severity: Optional[str]
    message: Optional[str]


class SemgrepResult(TypedDict, total=False):
    success: bool
    error: Optional[str]
    issues: List[SemgrepIssue]
    raw: Optional[JSONValue]


class SnykIssue(TypedDict, total=False):
    id: Optional[str]
    title: Optional[str]
    severity: Optional[str]
    priority: Optional[str]


class SnykResult(TypedDict, total=False):
    success: bool
    error: Optional[str]
    issues: List[Dict[str, JSONValue]]
    raw: Optional[JSONValue]


class EslintIssue(TypedDict, total=False):
    file: Optional[str]
    line: Optional[int]
    ruleId: Optional[str]
    severity: Optional[int]
    message: Optional[str]


class EslintResult(TypedDict, total=False):
    success: bool
    error: Optional[str]
    issues: List[EslintIssue]
    raw: Optional[JSONValue]


class CodeQLResult(TypedDict, total=False):
    success: bool
    error: Optional[str]
    issues: List[Dict[str, JSONValue]]
    raw: Optional[JSONValue]


def _run_cmd(cmd: list[str], timeout: int = DEFAULT_TIMEOUT) -> tuple[bool, str]:
    # Ensure the binary exists on PATH before attempting to run it.
    if not cmd:
        return False, "Commande vide"
    if shutil.which(cmd[0]) is None:
        return False, f"Commande introuvable: {cmd[0]}"
    try:
        # Ensure subprocesses use UTF-8 on Windows (avoid cp1252 encode/decode errors)
        env = os.environ.copy()
        env.setdefault("PYTHONUTF8", "1")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout, env=env)
    except FileNotFoundError:
        return False, f"Commande introuvable: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, f"Execution timeout apres {timeout}s: {cmd[0]}"
    if result.returncode not in (0, 1):
        return False, result.stderr.strip() or "Execution echouee"
    return True, result.stdout


def _pick_semgrep_config(language: Optional[str]) -> str:
    """Select semgrep config based on language, overridable via env."""
    lang = (language or "").lower()
    if lang == "python":
        return SEMGREP_CONFIG_PY
    if lang == "javascript":
        return SEMGREP_CONFIG_JS
    if lang == "typescript":
        return SEMGREP_CONFIG_TS
    if lang == "java":
        return SEMGREP_CONFIG_JAVA
    if lang in ("csharp", "c#"):
        return SEMGREP_CONFIG_CS
    return SEMGREP_CONFIG_DEFAULT


def run_semgrep(target: Path, language: Optional[str] = None) -> SemgrepResult:
    # On Windows semgrep often fails due to system encoding (cp1252). By default we
    # disable semgrep on Windows to avoid flaky UnicodeEncodeError unless the
    # operator explicitly forces it via FORCE_SEMGREP=1.
    if (sys.platform.startswith("win") or platform.system().lower().startswith("win")) and os.environ.get("FORCE_SEMGREP", "0") != "1":
        guidance = (
            "Semgrep desactive par defaut sur Windows a cause de problemes d'encodage. "
            "Pour forcer son execution, exportez `FORCE_SEMGREP=1` et assurez-vous que le serveur "
            "est lance avec `PYTHONUTF8=1` et `PYTHONIOENCODING=utf-8`, ou utilisez WSL/Docker."
        )
        return {"success": False, "error": guidance, "issues": [], "raw": None}

    # Try the semgrep binary first; if it fails due to encoding or missing binary,
    # fallback to invoking the module with the same Python interpreter (`python -m semgrep`).
    config = _pick_semgrep_config(language)
    cmd = ["semgrep", "--json", "--config", config, str(target)]
    success, output = _run_cmd(cmd)
    if not success:
        err = (output or "").lower()
        needs_fallback = False
        if "commande introuvable" in err or "not found" in err:
            needs_fallback = True
        if "charmap" in err or "codec" in err or "encoding" in err:
            needs_fallback = True

        if needs_fallback:
            py = sys.executable or "python"
            cmd2 = [py, "-m", "semgrep", "--json", "--config", config, str(target)]
            success2, output2 = _run_cmd(cmd2)
            if not success2:
                # If fallback also fails, detect common Windows encoding failure and return a helpful message.
                errtxt = (output2 or "").lower()
                if "charmap" in errtxt or "codec" in errtxt or "unicodeencodeerror" in errtxt:
                    guidance = (
                        "Semgrep a echoue a cause d'un probleme d'encodage sous Windows (cp1252). "
                        "Contournements:\n"
                        " - Executer le serveur avec la venv Python (par ex. `.venv\\Scripts\\python.exe`)\n"
                        " - Exporter `PYTHONUTF8=1` et `PYTHONIOENCODING=utf-8` avant de lancer le serveur\n"
                        " - Executer Semgrep sous WSL ou dans un conteneur Linux\n"
                        "Details de l'erreur: " + output2
                    )
                    return {"success": False, "error": guidance, "issues": [], "raw": None}
                return {"success": False, "error": output2, "issues": [], "raw": None}
            output = output2
            success = True
        else:
            return {"success": False, "error": output, "issues": [], "raw": None}
    try:
        data = json.loads(output or "{}")
    except json.JSONDecodeError:
        return {"success": False, "error": "Semgrep JSON invalide", "issues": [], "raw": None}
    issues: List[SemgrepIssue] = []
    for result in data.get("results", []):
        issues.append(
            {
                "path": result.get("path"),
                "start": result.get("start", {}).get("line"),
                "end": result.get("end", {}).get("line"),
                "check_id": result.get("check_id"),
                "severity": result.get("extra", {}).get("severity"),
                "message": result.get("extra", {}).get("message"),
            }
        )
    return {"success": True, "error": None, "issues": issues, "raw": data}


def run_snyk_code(target: Path) -> SnykResult:
    cmd = ["snyk", "code", "test", "--json"]
    if target.is_file():
        cmd += ["--file", str(target)]
    else:
        cmd.append(str(target))
    success, output = _run_cmd(cmd)
    if not success:
        return {"success": False, "error": output, "issues": [], "raw": None}
    try:
        data = json.loads(output or "{}")
    except json.JSONDecodeError:
        return {"success": False, "error": "Snyk JSON invalide", "issues": [], "raw": None}
    issues = data.get("issues", [])
    return {"success": True, "error": None, "issues": issues, "raw": data}


def run_eslint(target: Path) -> EslintResult:
    cmd = ["eslint", "-f", "json", str(target)]
    success, output = _run_cmd(cmd)
    if not success:
        return {"success": False, "error": output, "issues": [], "raw": None}
    try:
        data = json.loads(output or "[]")
    except json.JSONDecodeError:
        return {"success": False, "error": "ESLint JSON invalide", "issues": [], "raw": None}
    issues: List[EslintIssue] = []
    for file_entry in data:
        for msg in file_entry.get("messages", []):
            issues.append(
                {
                    "file": file_entry.get("filePath"),
                    "line": msg.get("line"),
                    "ruleId": msg.get("ruleId"),
                    "severity": msg.get("severity"),
                    "message": msg.get("message"),
                }
            )
    return {"success": True, "error": None, "issues": issues, "raw": data}


def run_codeql(target: Path) -> CodeQLResult:
    return {"success": False, "error": "CodeQL non configure dans cet environnement", "issues": [], "raw": None}


def aggregate_scans(target: Path) -> Dict[str, JSONValue]:
    return {
        "semgrep": run_semgrep(target),
        "snyk": run_snyk_code(target),
        "eslint": run_eslint(target),
        "codeql": run_codeql(target),
    }


def check_binaries() -> Dict[str, BinaryInfo]:
    """Return availability and basic version info for known scanner binaries.

    This helps an endpoint `/status` report which tools are present on the host.
    """
    tools = {
        "bandit": ["bandit", "--version"],
        "semgrep": ["semgrep", "--version"],
        "snyk": ["snyk", "--version"],
        "eslint": ["eslint", "--version"],
    }
    res: Dict[str, BinaryInfo] = {}
    for name, cmd in tools.items():
        if shutil.which(cmd[0]) is None:
            res[name] = {"available": False, "version": None}
            continue
        ok, out = _run_cmd(cmd, timeout=10)
        if not ok:
            res[name] = {"available": False, "version": None, "error": out}
            continue
        # Keep only the first non-empty line as a version hint
        ver = None
        if isinstance(out, str):
            for line in out.splitlines():
                if line.strip():
                    ver = line.strip()
                    break
        res[name] = {"available": True, "version": ver}
    return res
