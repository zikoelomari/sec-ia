from __future__ import annotations

import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, TypedDict


class BanditIssue(TypedDict, total=False):
    line: Optional[int]
    severity: Optional[str]
    confidence: Optional[str]
    test_id: Optional[str]
    test_name: Optional[str]
    text: Optional[str]
    filename: Optional[str]


class BanditResult(TypedDict, total=False):
    success: bool
    issues: List[BanditIssue]
    metrics: Dict[str, int]
    error: Optional[str]

# Default timeout (seconds) for analyzer subprocesses
_ANALYZER_TIMEOUT = 60


def analyze_python_code_with_bandit(code: str) -> BanditResult:
    """Run Bandit on the provided Python code snippet and return a structured dict."""
    response: BanditResult = {"success": False, "issues": [], "metrics": {}, "error": None}

    with tempfile.TemporaryDirectory(prefix="bandit_snippet_") as tmpdir:
        tmp_path = Path(tmpdir) / "snippet.py"
        tmp_path.write_text(code, encoding="utf-8")

        try:
            if shutil.which("bandit") is None:
                response["error"] = "Bandit n'est pas installe."
                return response
            result = subprocess.run(
                ["bandit", "-f", "json", "-q", str(tmp_path)],
                capture_output=True,
                text=True,
                check=False,
                timeout=_ANALYZER_TIMEOUT,
            )
        except FileNotFoundError:
            response["error"] = "Bandit n'est pas installe."
            return response
        except subprocess.TimeoutExpired:
            response["error"] = f"Bandit timeout apres {_ANALYZER_TIMEOUT}s"
            return response

        if result.returncode not in (0, 1):
            response["error"] = result.stderr.strip() or "Execution Bandit echouee."
            return response

        try:
            data = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            response["error"] = "Impossible de parser la sortie JSON de Bandit."
            return response

        issues: List[BanditIssue] = []
        for issue in data.get("results", []):
            issues.append(
                {
                    "line": issue.get("line_number"),
                    "severity": issue.get("issue_severity"),
                    "confidence": issue.get("issue_confidence"),
                    "test_id": issue.get("test_id"),
                    "test_name": issue.get("test_name"),
                    "text": issue.get("issue_text"),
                    "filename": issue.get("filename"),
                }
            )

        response.update(
            {
                "success": True,
                "issues": issues,
                "metrics": data.get("metrics", {}),
                "error": None,
            }
        )
        return response


def analyze_python_path_with_bandit(path: Path) -> BanditResult:
    """Run Bandit recursively on a path (file or directory) and return a structured dict."""
    response: BanditResult = {"success": False, "issues": [], "metrics": {}, "error": None}

    target = Path(path)
    if not target.exists():
        response["error"] = f"Chemin introuvable: {target}"
        return response

    cmd = ["bandit", "-f", "json", "-q"]
    if target.is_dir():
        cmd += ["-r", str(target)]
    else:
        cmd += [str(target)]

    try:
        if shutil.which("bandit") is None:
            response["error"] = "Bandit n'est pas installe."
            return response
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=_ANALYZER_TIMEOUT)
    except FileNotFoundError:
        response["error"] = "Bandit n'est pas installe."
        return response
    except subprocess.TimeoutExpired:
        response["error"] = f"Bandit timeout apres {_ANALYZER_TIMEOUT}s"
        return response

    if result.returncode not in (0, 1):
        response["error"] = result.stderr.strip() or "Execution Bandit echouee."
        return response

    try:
        data = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        response["error"] = "Impossible de parser la sortie JSON de Bandit."
        return response

    issues: List[BanditIssue] = []
    for issue in data.get("results", []):
        issues.append(
            {
                "line": issue.get("line_number"),
                "severity": issue.get("issue_severity"),
                "confidence": issue.get("issue_confidence"),
                "test_id": issue.get("test_id"),
                "test_name": issue.get("test_name"),
                "text": issue.get("issue_text"),
                "filename": issue.get("filename"),
            }
        )

    response.update(
        {
            "success": True,
            "issues": issues,
            "metrics": data.get("metrics", {}),
            "error": None,
        }
    )
    return response
