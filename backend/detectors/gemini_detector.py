from __future__ import annotations

import ast
import re
import os
from pathlib import Path
from typing import Dict, List, Optional, TypedDict

# Heuristics inspired by common generated-code detectors (tokens, dangerous calls, API key patterns)
_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*[\'\"]?[0-9A-Za-z\-_.]{16,}\b"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),  # Google API key pattern
    re.compile(r"sk_live_[0-9a-zA-Z]{24,}") , # Stripe live key
    re.compile(r"SG\.[A-Za-z0-9\-_.]{20,}"), # SendGrid
    re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}") , # Slack tokens
]


class DetectorIssue(TypedDict, total=False):
    type: str
    pattern: str
    match_masked: str
    match_length: int
    name: str
    attr: str
    call: str
    lineno: int
    file: str


class DetectorResult(TypedDict, total=False):
    success: bool
    error: Optional[str]
    issues: List[DetectorIssue]


def _scan_code_for_regex(code: str) -> List[DetectorIssue]:
    issues: List[DetectorIssue] = []
    for pat in _SECRET_PATTERNS:
        for m in pat.finditer(code):
            raw = m.group(0)
            # Mask secret matches before returning them to API clients
            def _mask(s: str) -> str:
                if os.environ.get("REVEAL_SECRETS", "0") == "1":
                    return s
                # show up to first 4 and last 4 chars
                if len(s) <= 8:
                    return "*" * len(s)
                return f"{s[:4]}...{s[-4:]}"

            issues.append({
                "type": "secret",
                "pattern": pat.pattern,
                "match_masked": _mask(raw),
                "match_length": len(raw),
            })
    return issues


class _CallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.issues: List[DetectorIssue] = []

    def visit_Call(self, node: ast.Call) -> None:
        # detect dynamic execution
        func = node.func
        if isinstance(func, ast.Name) and func.id in ("exec", "eval", "compile"):
            self.issues.append({"type": "dynamic_exec", "name": func.id, "lineno": node.lineno})

        # detect subprocess / os.system / Popen usage
        if isinstance(func, ast.Attribute):
            attr = func.attr
            if attr in ("Popen", "run", "call"):
                # record the attribute; full module may be in value
                self.issues.append({"type": "subprocess_call", "attr": attr, "lineno": node.lineno})
        if isinstance(func, ast.Name) and func.id in ("system",):
            self.issues.append({"type": "os_system", "name": func.id, "lineno": node.lineno})

        # detect HTTP clients calls by name heuristics (requests, httpx)
        if isinstance(func, ast.Attribute):
            if getattr(func.value, "id", None) in ("requests", "httpx") or getattr(func.value, "attr", None) in ("requests",):
                self.issues.append({"type": "http_client", "call": func.attr, "lineno": node.lineno})

        self.generic_visit(node)


def detect_code_string(code: str) -> DetectorResult:
    """Analyze a single Python source string and return heuristic findings."""
    results: DetectorResult = {"success": True, "issues": []}
    try:
        tree = ast.parse(code)
    except Exception as e:
        return {"success": False, "error": f"AST parse error: {e}", "issues": []}

    visitor = _CallVisitor()
    visitor.visit(tree)
    results["issues"].extend(visitor.issues)

    # regex secrets
    results["issues"].extend(_scan_code_for_regex(code))
    return results


def detect_path(path: Path) -> DetectorResult:
    """Walk a file or directory and run detection on .py files."""
    issues: List[DetectorIssue] = []
    target = Path(path)
    if target.is_file():
        try:
            code = target.read_text(encoding="utf-8")
        except Exception:
            return {"success": False, "error": f"Could not read file: {target}", "issues": []}
        det = detect_code_string(code)
        issues.extend(det.get("issues", []))
        return {"success": True, "issues": issues}

    for p in target.rglob("*.py"):
        try:
            code = p.read_text(encoding="utf-8")
        except Exception:
            continue
        det = detect_code_string(code)
        for it in det.get("issues", []):
            entry = dict(it)
            entry.setdefault("file", str(p))
            issues.append(entry)

    return {"success": True, "issues": issues}
