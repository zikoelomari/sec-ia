import streamlit as st
import requests
import json
import pandas as pd
import os
import hashlib
from pathlib import Path
from typing import Optional, Dict, List
import io
from datetime import datetime, timezone
from urllib.parse import urlparse

# Optional matplotlib imports
try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    plt = None

# IMPORTANT: set_page_config() doit être la première commande Streamlit
st.set_page_config(
    page_title="Security Analysis Platform - Unifié",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Configuration globale dans la sidebar
st.sidebar.title("⚙️ Configuration")
API_BASE_URL = st.sidebar.text_input("URL de l'API", value="http://localhost:8000")
API_KEY = st.sidebar.text_input("API Key (optionnel)", type="password")
REPO_ROOT = Path(__file__).resolve().parents[1]

# Vérifier le statut de l'API
@st.cache_data(ttl=60)
def check_api_status():
    """Vérifier si l'API est accessible."""
    try:
        response = requests.get(f"{API_BASE_URL}/api", timeout=5)
        return response.status_code == 200
    except:
        return False

# ============================================
# FONCTIONS UTILITAIRES (définies avant utilisation)
# ============================================

def calculate_metrics(scanners_data: dict) -> tuple:
    """Calcule les métriques depuis les données des scanners."""
    high_count = 0
    med_count = 0
    low_count = 0
    
    for scanner_name, scanner_data in scanners_data.items():
        if scanner_name == "_meta":
            continue
        if isinstance(scanner_data, dict):
            issues = scanner_data.get("issues", [])
            for issue in issues:
                sev = issue.get("severity", "").upper()
                if sev == "HIGH" or sev == "ERROR":
                    high_count += 1
                elif sev == "MEDIUM" or sev == "WARNING":
                    med_count += 1
                elif sev == "LOW" or sev == "INFO":
                    low_count += 1
    
    # Patterns du detector
    if "gemini_detector" in scanners_data or "gemini_detector_snippet" in scanners_data:
        detector_data = scanners_data.get("gemini_detector_snippet") or scanners_data.get("gemini_detector", {})
        if isinstance(detector_data, dict):
            patterns = detector_data.get("patterns", {})
            med_count += sum(1 for v in patterns.values() if v > 0)
            issues = detector_data.get("issues", [])
            if isinstance(issues, list):
                med_count += len(issues)
    
    risk_score = high_count * 5 + med_count * 2 + low_count * 1
    
    return high_count, med_count, low_count, risk_score


def _convert_cli_scans(scans: dict) -> dict:
    converted = {}

    bandit = scans.get("bandit")
    if isinstance(bandit, dict):
        issues = []
        for issue in bandit.get("results", []):
            issues.append({
                "severity": (issue.get("issue_severity") or "").upper(),
                "text": issue.get("issue_text", ""),
                "test_id": issue.get("test_id", ""),
                "line": issue.get("line_number", ""),
            })
        converted["bandit"] = {"issues": issues}

    semgrep = scans.get("semgrep")
    if isinstance(semgrep, dict):
        issues = []
        for result in semgrep.get("results", []):
            extra = result.get("extra", {}) if isinstance(result, dict) else {}
            issues.append({
                "severity": (extra.get("severity") or "").upper(),
                "message": extra.get("message", ""),
                "check_id": result.get("check_id", "") if isinstance(result, dict) else "",
                "start": result.get("start", {}) if isinstance(result, dict) else {},
            })
        converted["semgrep"] = {"issues": issues}

    snyk = scans.get("snyk")
    if isinstance(snyk, dict):
        issues = snyk.get("issues", [])
        converted["snyk"] = {"issues": issues}

    return converted

def extract_scanners_data(report_data: dict) -> dict:
    if not isinstance(report_data, dict):
        return {}
    scanners = report_data.get("scanners")
    if isinstance(scanners, dict):
        return scanners
    analysis = report_data.get("analysis")
    if isinstance(analysis, dict) and isinstance(analysis.get("scanners"), dict):
        return analysis["scanners"]
    scans = report_data.get("scans")
    if isinstance(scans, dict):
        return _convert_cli_scans(scans)
    return {}

def _normalize_scanners(scanners: Optional[List[str]]) -> List[str]:
    if not scanners:
        return []
    normalized = {s.strip().lower() for s in scanners if isinstance(s, str) and s.strip()}
    return sorted(normalized)


def _request_hash(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _get_reports_dir() -> Optional[Path]:
    reports_env = os.environ.get("REPORTS_DIR", "analyses")
    reports_dir = Path(reports_env)
    if not reports_dir.is_absolute():
        reports_dir = REPO_ROOT / reports_dir
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        return reports_dir
    except Exception:
        return None


def _iter_report_entries() -> List[Dict[str, object]]:
    reports_dir = _get_reports_dir()
    if not reports_dir or not reports_dir.exists():
        return []

    entries: List[Dict[str, object]] = []
    report_files = sorted(reports_dir.glob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for report_path in report_files:
        try:
            with report_path.open("r", encoding="utf-8") as handle:
                report_data = json.load(handle)
        except Exception:
            continue
        entries.append({"path": report_path, "data": report_data})
    return entries


def _get_report_request_hash(report_data: dict) -> Optional[str]:
    if not isinstance(report_data, dict):
        return None

    metadata = report_data.get("metadata", {})
    if isinstance(metadata, dict):
        request_hash = metadata.get("request_hash")
        if isinstance(request_hash, str) and request_hash:
            return request_hash
        request_meta = metadata.get("request")
        if isinstance(request_meta, dict):
            return _request_hash(request_meta)

    request_hash = report_data.get("request_hash")
    if isinstance(request_hash, str) and request_hash:
        return request_hash

    request_meta = report_data.get("request")
    if isinstance(request_meta, dict):
        return _request_hash(request_meta)

    return None


def _normalize_github_url(raw_url: str) -> str:
    trimmed = (raw_url or "").strip()
    if not trimmed:
        return ""

    parsed = urlparse(trimmed)
    if not parsed.netloc:
        parsed = urlparse(f"https://{trimmed}")

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        return trimmed

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = parts[3]

    base = f"https://github.com/{owner}/{repo}"
    if branch:
        return f"{base}/tree/{branch}"
    return base


def _repo_id_to_url(repo_id: str) -> str:
    if not repo_id:
        return ""
    raw = str(repo_id)
    base, _, branch = raw.partition("@")
    if "/" not in base:
        return ""
    url = f"https://github.com/{base}"
    if branch:
        url = f"{url}/tree/{branch}"
    return url


def _find_duplicate_report(report_entries: List[Dict[str, object]], request_meta: dict, report_type: Optional[str] = None) -> Optional[Dict[str, object]]:
    request_hash = _request_hash(request_meta)
    for entry in report_entries:
        report_data = entry.get("data", {})
        if report_type:
            if _infer_report_type(report_data, entry["path"].name) != report_type:
                continue
        if _get_report_request_hash(report_data) == request_hash:
            return entry
    return None


def _find_duplicate_github_report(report_entries: List[Dict[str, object]], normalized_url: str, scanners: List[str]) -> Optional[Dict[str, object]]:
    request_meta = {
        "type": "github",
        "url": normalized_url,
        "scanners": scanners,
    }
    match = _find_duplicate_report(report_entries, request_meta, report_type="github")
    if match:
        return match

    if not normalized_url:
        return None

    for entry in report_entries:
        report_data = entry.get("data", {})
        if _infer_report_type(report_data, entry["path"].name) != "github":
            continue
        repo_url = _repo_id_to_url(report_data.get("repo", ""))
        if repo_url and _normalize_github_url(repo_url) == normalized_url:
            report_scanners = _normalize_scanners([k for k in extract_scanners_data(report_data).keys() if k != "_meta"])
            if not scanners or report_scanners == scanners:
                return entry
    return None

def build_findings_list(scanners_data: dict, severity_filter: Optional[List[str]] = None, scanner_filter: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """Build a unified list of findings for UI tables."""
    severity_filter = severity_filter or ["HIGH", "MEDIUM", "LOW"]
    scanner_filter = scanner_filter or ["bandit", "semgrep", "snyk", "gemini_detector"]
    findings_list: List[Dict[str, str]] = []

    # Bandit findings
    if "bandit" in scanners_data and "bandit" in scanner_filter:
        bandit_data = scanners_data["bandit"]
        if isinstance(bandit_data, dict) and "issues" in bandit_data:
            for issue in bandit_data["issues"]:
                sev = issue.get("severity", "").upper()
                if sev in severity_filter:
                    findings_list.append({
                        "Scanner": "Bandit",
                        "Severite": sev,
                        "Type": issue.get("test_id", ""),
                        "Message": issue.get("text", "")[:100],
                        "Ligne": issue.get("line", ""),
                    })

    # Semgrep findings
    if "semgrep" in scanners_data and "semgrep" in scanner_filter:
        semgrep_data = scanners_data["semgrep"]
        if isinstance(semgrep_data, dict) and "issues" in semgrep_data:
            for issue in semgrep_data["issues"]:
                sev = issue.get("severity", "").upper()
                if sev in severity_filter or (sev not in ["HIGH", "MEDIUM", "LOW"] and "MEDIUM" in severity_filter):
                    findings_list.append({
                        "Scanner": "Semgrep",
                        "Severite": sev if sev in ["HIGH", "MEDIUM", "LOW"] else "MEDIUM",
                        "Type": issue.get("check_id", ""),
                        "Message": issue.get("message", "")[:100],
                        "Ligne": issue.get("start", {}).get("line", "") if isinstance(issue.get("start"), dict) else "",
                    })

    # Snyk findings
    if "snyk" in scanners_data and "snyk" in scanner_filter:
        snyk_data = scanners_data["snyk"]
        if isinstance(snyk_data, dict) and "issues" in snyk_data:
            for issue in snyk_data["issues"]:
                sev = issue.get("severity", "").upper()
                if sev in severity_filter:
                    findings_list.append({
                        "Scanner": "Snyk",
                        "Severite": sev,
                        "Type": issue.get("id", ""),
                        "Message": issue.get("title", "")[:100],
                        "Ligne": "",
                    })

    # Detector findings (issues or patterns)
    if ("gemini_detector" in scanners_data or "gemini_detector_snippet" in scanners_data) and "gemini_detector" in scanner_filter:
        detector_data = scanners_data.get("gemini_detector_snippet") or scanners_data.get("gemini_detector", {})
        if isinstance(detector_data, dict):
            issues = detector_data.get("issues", [])
            if isinstance(issues, list):
                for issue in issues:
                    if "MEDIUM" in severity_filter:
                        msg = issue.get("pattern") or issue.get("name") or issue.get("attr") or issue.get("call") or ""
                        findings_list.append({
                            "Scanner": "Detector",
                            "Severite": "MEDIUM",
                            "Type": issue.get("type", ""),
                            "Message": msg,
                            "Ligne": issue.get("lineno", ""),
                        })
            patterns = detector_data.get("patterns", {})
            if isinstance(patterns, dict):
                for pattern_name, count in patterns.items():
                    if count > 0 and "MEDIUM" in severity_filter:
                        findings_list.append({
                            "Scanner": "Detector",
                            "Severite": "MEDIUM",
                            "Type": pattern_name,
                            "Message": f"Pattern detecte {count} fois",
                            "Ligne": "",
                        })

    return findings_list


def _parse_report_datetime(report_data: dict, report_path: Path) -> datetime:
    candidates = []
    metadata = report_data.get("metadata", {})
    if isinstance(metadata, dict):
        candidates.append(metadata.get("timestamp"))
    generation = report_data.get("generation")
    if isinstance(generation, dict):
        candidates.append(generation.get("timestamp"))
    candidates.append(report_data.get("generated_at"))

    for ts in candidates:
        if isinstance(ts, str) and ts:
            val = ts.replace("Z", "+00:00")
            try:
                parsed = datetime.fromisoformat(val)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue

    try:
        file_ts = datetime.fromtimestamp(report_path.stat().st_mtime, tz=timezone.utc)
        return file_ts
    except Exception:
        return datetime.utcnow().replace(tzinfo=timezone.utc)


def _infer_report_type(report_data: dict, report_name: str) -> str:
    if isinstance(report_data.get("generation"), dict):
        return "generation"

    metadata = report_data.get("metadata", {})
    if isinstance(metadata, dict):
        raw_type = str(metadata.get("type", "")).lower()
        if "repo" in raw_type:
            return "github"
        if "snippet" in raw_type or "code" in raw_type:
            return "code"

    if report_data.get("repo"):
        return "github"
    if report_name.startswith("report_repo"):
        return "github"
    if report_name.startswith("report_snippet"):
        return "code"
    if isinstance(report_data.get("analysis"), dict):
        return "code"

    return "unknown"


def _severity_bucket(high_count: int, med_count: int, low_count: int) -> str:
    if high_count > 0:
        return "HIGH"
    if med_count > 0:
        return "MEDIUM"
    if low_count > 0:
        return "LOW"
    return "NONE"


def display_results(result: dict, analysis_type: str, code_input: str = "", compact: bool = False):
    """Affiche les résultats d'analyse de manière formatée."""
    st.header("📊 Résultats de l'analyse")
    
    scanners_data = result.get("scanners", {})
    
    # Calculer les métriques
    high_count, med_count, low_count, risk_score = calculate_metrics(scanners_data)
    
    # Métriques
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("HIGH", high_count, delta=None)
    with col2:
        st.metric("MEDIUM", med_count, delta=None)
    with col3:
        st.metric("LOW", low_count, delta=None)
    with col4:
        st.metric("Risk Score", risk_score, delta=None)
    
    # Informations supplémentaires pour GitHub
    if analysis_type == "github":
        if "repo" in result:
            st.info(f"📦 Dépôt analysé: {result['repo']}")
    
    if compact:
        st.subheader("Resume rapide")
        summary_rows = []

        for scanner_name, scanner_data in scanners_data.items():
            if scanner_name in ("_meta", "gemini_detector", "gemini_detector_snippet"):
                continue
            issues = scanner_data.get("issues", []) if isinstance(scanner_data, dict) else []
            summary_rows.append({
                "Scanner": scanner_name,
                "Issues": len(issues),
            })

        detector_data = scanners_data.get("gemini_detector_snippet") or scanners_data.get("gemini_detector", {})
        if isinstance(detector_data, dict):
            patterns = detector_data.get("patterns", {})
            issues = detector_data.get("issues", [])
            total_patterns = 0
            if patterns:
                total_patterns = sum(int(v) for v in patterns.values())
            total_issues = len(issues) if isinstance(issues, list) else 0
            if total_patterns + total_issues > 0:
                summary_rows.append({
                    "Scanner": "Detector",
                    "Issues": total_patterns + total_issues,
                })

        if summary_rows:
            st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)
        else:
            st.info("Aucun resultat a afficher")
        return

    # Filtres
    st.subheader("🔍 Findings")
    
    col_filter1, col_filter2 = st.columns(2)
    with col_filter1:
        severity_filter = st.multiselect(
            "Filtrer par sévérité",
            ["HIGH", "MEDIUM", "LOW"],
            default=["HIGH", "MEDIUM", "LOW"],
            key=f"severity_filter_{analysis_type}"
        )
    with col_filter2:
        scanner_filter = st.multiselect(
            "Filtrer par scanner",
            ["bandit", "semgrep", "snyk", "gemini_detector"],
            default=["bandit", "semgrep", "snyk", "gemini_detector"],
            key=f"scanner_filter_{analysis_type}"
        )
    
    # Table des findings
    findings_list = build_findings_list(scanners_data, severity_filter, scanner_filter)


    if findings_list:
        df = pd.DataFrame(findings_list)
        st.dataframe(df, use_container_width=True, height=400)
    else:
        st.info("✅ Aucune finding trouvée avec les filtres sélectionnés")
    
    # Recommandations
    st.subheader("💡 Recommandations")
    
    recommendations = []
    if high_count > 0:
        recommendations.append("🔴 Vulnérabilités HIGH détectées: Réviser le code avant déploiement")
    if "secrets" in str(findings_list).lower() or "password" in str(findings_list).lower():
        recommendations.append("🔐 Secrets potentiels détectés: Utiliser des variables d'environnement ou un vault")
    if "injection" in str(findings_list).lower() or "sql" in str(findings_list).lower():
        recommendations.append("💉 Risques d'injection: Valider et sanitizer toutes les entrées utilisateur")
    if "subprocess" in str(findings_list).lower() or "exec" in str(findings_list).lower():
        recommendations.append("⚡ Exécution de code détectée: Vérifier que les commandes sont sécurisées")
    if risk_score > 10:
        recommendations.append("⚠️ Risk score élevé: Considérer une revue de code approfondie")
    
    if recommendations:
        for rec in recommendations:
            st.warning(rec)
    else:
        st.success("✅ Aucune recommandation critique")
    
    # Export
    st.subheader("📥 Export")
    
    col_exp1, col_exp2 = st.columns(2)
    
    with col_exp1:
        # Export JSON
        json_str = json.dumps(result, indent=2, ensure_ascii=False)
        st.download_button(
            label="📄 Télécharger JSON",
            data=json_str,
            file_name=f"security_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
    
    with col_exp2:
        # Export PDF via API
        if st.button("📑 Générer PDF", use_container_width=True):
            try:
                headers = {"Content-Type": "application/json"}
                if API_KEY:
                    headers["X-API-KEY"] = API_KEY
                
                # Créer un rapport simplifié pour l'export PDF
                pdf_request = {
                    "language": result.get("language", "python"),
                    "code": code_input if analysis_type == "code" else "",
                    "scanners": scanners_data,
                    "summary": {
                        "severity": {
                            "HIGH": high_count,
                            "MEDIUM": med_count,
                            "LOW": low_count,
                        },
                        "risk_score": risk_score,
                    }
                }
                
                response = requests.post(
                    f"{API_BASE_URL}/export-pdf",
                    json=pdf_request,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    st.download_button(
                        label="📑 Télécharger PDF",
                        data=response.content,
                        file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mime="application/pdf",
                        use_container_width=True
                    )
                else:
                    st.error(f"Erreur génération PDF: {response.status_code}")
            except Exception as e:
                st.error(f"Erreur: {str(e)}")

def display_generation_result(result: dict):
    generation = result.get("generation", {}) if isinstance(result, dict) else {}
    analysis = result.get("analysis", {}) if isinstance(result, dict) else {}

    provider = generation.get("provider", "N/A")
    model = generation.get("model", "N/A")
    st.success(f"Code genere avec succes ({provider} - {model})")

    col_tokens, col_cost, col_time = st.columns(3)
    with col_tokens:
        st.metric("Tokens utilises", generation.get("tokens_used", 0))
    with col_cost:
        cost = generation.get("cost_usd", 0) or 0
        st.metric("Cout estime", f"${cost:.4f}" if cost else "Gratuit")
    with col_time:
        duration = generation.get("metadata", {}).get("duration_seconds", 0)
        st.metric("Duree", f"{duration:.2f}s" if duration else "N/A")

    st.subheader("Code genere")
    display_language = analysis.get("language") or "python"
    st.code(generation.get("code", ""), language=display_language)

    st.subheader("Resultats de l'analyse de securite")
    scanners_data = analysis.get("scanners", {})
    high_count, med_count, low_count, risk_score = calculate_metrics(scanners_data)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("HIGH", high_count)
    with col2:
        st.metric("MEDIUM", med_count)
    with col3:
        st.metric("LOW", low_count)
    with col4:
        st.metric("Risk Score", risk_score)

    for scanner_name, scanner_result in scanners_data.items():
        if isinstance(scanner_result, dict) and scanner_result.get("success"):
            with st.expander(f"Resultats {scanner_name.upper()}", expanded=False):
                issues = scanner_result.get("issues", [])
                if issues:
                    st.write(f"**{len(issues)} issue(s) detectee(s)**")
                    for issue in issues[:10]:
                        severity = issue.get("severity", "UNKNOWN")
                        message = issue.get("message", issue.get("title", "N/A"))
                        st.write(f"- [{severity}] {message}")
                else:
                    st.success("Aucune issue detectee")

api_status = check_api_status()
if api_status:
    st.sidebar.success("✅ API connectée")
else:
    st.sidebar.error("❌ API non accessible")

# Options scanners globales (utilisées dans tous les onglets)
st.sidebar.markdown("### 🔧 Options de scan (Globales)")
st.sidebar.markdown("*Ces options s'appliquent à tous les onglets*")
default_scanners = {
    "bandit": st.sidebar.checkbox("Bandit", value=True, key="default_bandit"),
    "semgrep": st.sidebar.checkbox("Semgrep", value=False, key="default_semgrep"),
    "snyk": st.sidebar.checkbox("Snyk", value=False, key="default_snyk"),
    "gemini_detector": st.sidebar.checkbox("Détecteur Gemini", value=True, key="default_detector"),
}

# Thème personnalisé
st.markdown("""
<style>
    /* Metrics cards avec gradient */
    div[data-testid="metric-container"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    div[data-testid="metric-container"] label {
        color: white !important;
        font-weight: 600;
    }
    
    div[data-testid="metric-container"] div {
        color: white !important;
    }
    
    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
    
    /* Main container */
    .main {
        background-color: #f8f9fa;
    }
    
    /* Buttons */
    .stButton button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 10px 24px;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px 8px 0 0;
        padding: 10px 24px;
        background-color: white;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    
    /* Success/warning/error messages */
    .stSuccess {
        background-color: #d4edda;
        border-left: 4px solid #28a745;
    }
    
    .stWarning {
        background-color: #fff3cd;
        border-left: 4px solid #ffc107;
    }
    
    .stError {
        background-color: #f8d7da;
        border-left: 4px solid #dc3545;
    }
</style>
""", unsafe_allow_html=True)

# Onglets principaux
nav_items = [
    ("gen", "Generation IA"),
    ("code", "Analyse de Code"),
    ("github", "Analyse GitHub"),
    ("dash", "Dashboard"),
    ("hist", "Historique"),
    ("help", "Aide"),
]
nav_labels = [label for _, label in nav_items]
nav_key_by_label = {label: key for key, label in nav_items}

active_label = st.radio(
    "Navigation",
    nav_labels,
    horizontal=True,
    label_visibility="collapsed",
    key="main_nav",
)
active_tab = nav_key_by_label.get(active_label, "gen")

# ============================================

# TAB 1: GÉNÉRATION IA
# ============================================
if active_tab == "gen":
    st.header("🤖 Générer du Code avec IA et Analyser")
    
    # Vérifier les providers disponibles
    try:
        providers_resp = requests.get(f"{API_BASE_URL}/api/providers", timeout=5)
        if providers_resp.status_code == 200:
            providers_data = providers_resp.json()
            available_providers = providers_data.get("available_providers", ["simulate"])
            
            # Afficher le statut
            col_openai, col_anthropic = st.columns(2)
            with col_openai:
                if providers_data.get("openai_configured"):
                    st.success("✅ OpenAI configuré")
                else:
                    st.info("ℹ️ OpenAI non configuré (optionnel)")
            with col_anthropic:
                if providers_data.get("anthropic_configured"):
                    st.success("✅ Anthropic configuré")
                else:
                    st.info("ℹ️ Anthropic non configuré (optionnel)")
        else:
            available_providers = ["simulate"]
            st.warning("Impossible de vérifier les providers, utilisation de 'simulate' par défaut")
    except:
        available_providers = ["simulate"]
        st.error("API non accessible. Vérifiez que le backend est démarré.")
    
    # Formulaire de génération
    col1, col2 = st.columns(2)
    
    with col1:
        description = st.text_area(
            "Description du code à générer",
            placeholder="Ex: API REST with JWT authentication and user registration",
            height=100,
            key="gen_description"
        )
        
        language = st.selectbox(
            "Langage cible",
            ["python", "javascript", "typescript", "java", "csharp"],
            key="gen_language"
        )
    
    with col2:
        provider = st.selectbox(
            "Provider IA",
            available_providers,
            help="OpenAI = GPT-4, Anthropic = Claude, Simulate = Templates",
            key="gen_provider"
        )
        
        temperature = st.slider(
            "Température (créativité)",
            min_value=0.0,
            max_value=1.0,
            value=0.7,
            step=0.1,
            help="0.0 = déterministe, 1.0 = créatif",
            key="gen_temperature"
        )
        
        max_tokens = st.number_input(
            "Tokens maximum",
            min_value=100,
            max_value=2000,
            value=500,
            step=100,
            key="gen_max_tokens"
        )
    
    # Utiliser les scanners globaux de la sidebar
    selected_scanners = [name for name, enabled in default_scanners.items() if enabled]
    normalized_scanners = _normalize_scanners(selected_scanners)
    
    # Bouton de génération
    if st.button("🚀 Générer et Analyser", type="primary", use_container_width=True, key="gen_analyze_btn"):
        if not description:
            st.error("Veuillez saisir une description du code à générer")
        else:
            report_entries = _iter_report_entries()
            request_meta = {
                "type": "generation",
                "description": description,
                "language": language,
                "provider": provider,
                "model": None,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "scanners": normalized_scanners,
            }
            duplicate = _find_duplicate_report(report_entries, request_meta, report_type="generation")
            if duplicate:
                st.session_state["last_generation_result"] = duplicate["data"]
                st.session_state["last_generation_duplicate"] = True
            else:
                with st.spinner(f"Génération avec {provider}... ⏳"):
                    try:
                        headers = {}
                        if API_KEY:
                            headers["X-API-KEY"] = API_KEY
                        
                        payload = {
                            "description": description,
                            "language": language,
                            "provider": provider,
                            "temperature": temperature,
                            "max_tokens": max_tokens,
                            "scanners": selected_scanners,
                        }
                        
                        response = requests.post(
                            f"{API_BASE_URL}/generate-and-analyze",
                            json=payload,
                            headers=headers,
                            timeout=60
                        )
                        
                        if response.status_code == 200:
                            result = response.json()
                            st.session_state["last_generation_result"] = result
                            st.session_state["last_generation_duplicate"] = False
                        elif response.status_code == 429:
                            st.error("Rate limit dépassé. Attendez quelques secondes.")
                        else:
                            st.error(f"Erreur API : {response.status_code} - {response.text}")
                    
                    except requests.exceptions.Timeout:
                        st.error("Timeout : la génération a pris trop de temps (>60s)")
                    except Exception as e:
                        st.error(f"Erreur : {e}")

    if "last_generation_result" in st.session_state:
        if st.session_state.get("last_generation_duplicate"):
            st.info("Analyse deja effectuee. Rapport charge depuis l'historique.")
        display_generation_result(st.session_state["last_generation_result"])

# ============================================
# TAB 2: ANALYSE DE CODE
# ============================================
if active_tab == "code":
    st.header("🔒 Analyse de Code en Temps Réel")
    st.markdown("Analysez votre code pour détecter les vulnérabilités de sécurité")
    
    language = st.selectbox(
        "Langage",
        ["python", "javascript", "typescript", "java", "csharp"],
        index=0
    )
    
    # Utiliser les scanners globaux de la sidebar
    selected_scanners = [name for name, enabled in default_scanners.items() if enabled]
    normalized_scanners = _normalize_scanners(selected_scanners)
    
    # Zone de code
    code_input = st.text_area(
        "Collez votre code ici",
        height=300,
        placeholder="""# Exemple Python
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return execute_query(query)
"""
    )
    
    col_analyze, col_fast = st.columns([1, 1])
    
    with col_analyze:
        analyze_btn = st.button("🔍 Analyser (Complet)", type="primary", use_container_width=True)
    
    with col_fast:
        analyze_fast_btn = st.button("⚡ Analyser (Rapide)", use_container_width=True)
    
    # Analyse complète
    if analyze_btn:
        if not code_input.strip():
            st.error("Veuillez entrer du code à analyser")
        else:
            report_entries = _iter_report_entries()
            request_meta = {
                "type": "code",
                "mode": "full",
                "language": language,
                "scanners": normalized_scanners,
                "code_sha256": hashlib.sha256(code_input.encode("utf-8")).hexdigest(),
                "code_len": len(code_input),
            }
            duplicate = _find_duplicate_report(report_entries, request_meta, report_type="code")
            if duplicate:
                st.session_state["last_code_result"] = duplicate["data"]
                st.session_state["last_analysis_type"] = "code"
                st.session_state["last_code_duplicate"] = True
            else:
                with st.spinner("Analyse en cours..."):
                    try:
                        headers = {"Content-Type": "application/json"}
                        if API_KEY:
                            headers["X-API-KEY"] = API_KEY
                        
                        body = {
                            "language": language,
                            "code": code_input,
                            "scanners": selected_scanners if selected_scanners else None,
                        }
                        
                        response = requests.post(
                            f"{API_BASE_URL}/analyze",
                            json=body,
                            headers=headers,
                            timeout=30
                        )
                        
                        if response.status_code == 200:
                            result = response.json()
                            st.session_state["last_code_result"] = result
                            st.session_state["last_analysis_type"] = "code"
                            st.session_state["last_code_duplicate"] = False
                            st.success("✅ Analyse terminée!")
                        else:
                            st.error(f"❌ Erreur API: {response.status_code} - {response.text}")
                    except Exception as e:
                        st.error(f"❌ Erreur: {str(e)}")

    # Analyse rapide
    if analyze_fast_btn:
        if not code_input.strip():
            st.error("Veuillez entrer du code à analyser")
        elif language != "python":
            st.warning("⚠️ L'analyse rapide est disponible uniquement pour Python")
        else:
            report_entries = _iter_report_entries()
            request_meta = {
                "type": "code",
                "mode": "fast",
                "language": language,
                "scanners": ["bandit", "gemini_detector"],
                "code_sha256": hashlib.sha256(code_input.encode("utf-8")).hexdigest(),
                "code_len": len(code_input),
            }
            duplicate = _find_duplicate_report(report_entries, request_meta, report_type="code")
            if duplicate:
                st.session_state["last_code_result"] = duplicate["data"]
                st.session_state["last_analysis_type"] = "code_fast"
                st.session_state["last_code_duplicate"] = True
            else:
                with st.spinner("Analyse rapide en cours..."):
                    try:
                        headers = {"Content-Type": "application/json"}
                        if API_KEY:
                            headers["X-API-KEY"] = API_KEY
                        
                        body = {
                            "language": language,
                            "code": code_input,
                        }
                        
                        response = requests.post(
                            f"{API_BASE_URL}/analyze-fast",
                            json=body,
                            headers=headers,
                            timeout=15
                        )
                        
                        if response.status_code == 200:
                            result = response.json()
                            st.session_state["last_code_result"] = result
                            st.session_state["last_analysis_type"] = "code_fast"
                            st.session_state["last_code_duplicate"] = False
                            st.success("✅ Analyse rapide terminée!")
                        else:
                            st.error(f"❌ Erreur API: {response.status_code}")
                    except Exception as e:
                        st.error(f"❌ Erreur: {str(e)}")

    # Afficher les résultats de l'analyse de code
    analysis_type = st.session_state.get("last_analysis_type", "code")
    if "last_code_result" in st.session_state and analysis_type.startswith("code"):
        if st.session_state.get("last_code_duplicate"):
            st.info("Analyse deja effectuee. Rapport charge depuis l'historique.")
        display_results(
            st.session_state["last_code_result"],
            analysis_type,
            code_input,
            compact=(analysis_type == "code_fast"),
        )

# ============================================
# TAB 3: ANALYSE GITHUB
# ============================================
if active_tab == "github":
    st.header("🐙 Analyse de Dépôt GitHub")
    st.markdown("Analysez un dépôt GitHub complet pour détecter les vulnérabilités")
    
    col_url, col_btn = st.columns([4, 1])
    
    with col_url:
        repo_url = st.text_input(
            "URL du dépôt GitHub",
            placeholder="https://github.com/OWNER/REPO ou https://github.com/OWNER/REPO/tree/branch",
            key="github_url_input"
        )
    
    with col_btn:
        st.write("")  # Espacement
        st.write("")  # Espacement
        analyze_github_btn = st.button("🔍 Analyser", type="primary", use_container_width=True)
    
    if repo_url:
        # Validation de l'URL
        if "github.com" not in repo_url:
            st.warning("⚠️ L'URL doit être une URL GitHub valide")
        else:
            st.info(f"📋 Dépôt à analyser: `{repo_url}`")
    
    # Utiliser les scanners globaux de la sidebar
    selected_github_scanners = [name for name, enabled in default_scanners.items() if enabled]
    normalized_github_scanners = _normalize_scanners(selected_github_scanners)
    
    if analyze_github_btn:
        if not repo_url.strip():
            st.error("? Veuillez entrer une URL GitHub")
        else:
            normalized_url = _normalize_github_url(repo_url)
            report_entries = _iter_report_entries()
            duplicate = _find_duplicate_github_report(report_entries, normalized_url, normalized_github_scanners)
            if duplicate:
                st.session_state["last_github_result"] = duplicate["data"]
                st.session_state["last_analysis_type"] = "github"
                st.session_state["last_github_duplicate"] = True
            else:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                try:
                    status_text.text("?? T?l?chargement du d?p?t...")
                    progress_bar.progress(20)
                    
                    headers = {"Content-Type": "application/json"}
                    if API_KEY:
                        headers["X-API-KEY"] = API_KEY
                    
                    body = {
                        "url": repo_url.strip(),
                        "scanners": selected_github_scanners if selected_github_scanners else None,
                    }
                    
                    status_text.text("?? Analyse en cours... (cela peut prendre plusieurs minutes)")
                    progress_bar.progress(40)
                    
                    response = requests.post(
                        f"{API_BASE_URL}/analyze-github",
                        json=body,
                        headers=headers,
                        timeout=300  # 5 minutes pour les gros d?p?ts
                    )
                    
                    progress_bar.progress(80)
                    
                    if response.status_code == 200:
                        result = response.json()
                        st.session_state["last_github_result"] = result
                        st.session_state["last_analysis_type"] = "github"
                        st.session_state["last_github_duplicate"] = False
                        progress_bar.progress(100)
                        status_text.text("? Analyse termin?e!")
                        st.success(f"? D?p?t analys?: {result.get('repo', 'N/A')}")
                    else:
                        progress_bar.empty()
                        error_msg = f"Erreur {response.status_code}"
                        try:
                            error_data = response.json()
                            error_msg += f": {error_data.get('detail', response.text)}"
                        except:
                            error_msg += f": {response.text}"
                        st.error(f"? {error_msg}")
                        status_text.empty()
                        
                except requests.exceptions.Timeout:
                    progress_bar.empty()
                    status_text.empty()
                    st.error("?? Timeout: L'analyse prend trop de temps. Essayez avec moins de scanners.")
                except Exception as e:
                    progress_bar.empty()
                    status_text.empty()
                    st.error(f"? Erreur: {str(e)}")

    # Afficher les résultats GitHub
    if "last_github_result" in st.session_state and st.session_state.get("last_analysis_type") == "github":
        if st.session_state.get("last_github_duplicate"):
            st.info("Analyse deja effectuee. Rapport charge depuis l'historique.")
        display_results(st.session_state["last_github_result"], "github", "")

# ============================================
# TAB 5: DASHBOARD
# ============================================
if active_tab == "dash":
    st.header("📊 Dashboard des Analyses")
    
    # Récupérer le dernier résultat
    last_result = None
    if "last_code_result" in st.session_state:
        last_result = st.session_state["last_code_result"]
        result_type = "Code"
    elif "last_github_result" in st.session_state:
        last_result = st.session_state["last_github_result"]
        result_type = "GitHub"
    
    if last_result:
        st.subheader(f"📈 Statistiques - Dernière analyse ({result_type})")
        
        # Calculer les métriques
        scanners_data = last_result.get("scanners", {})
        high_count, med_count, low_count, risk_score = calculate_metrics(scanners_data)
        
        # Métriques en colonnes
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("HIGH", high_count, delta=None)
        with col2:
            st.metric("MEDIUM", med_count, delta=None)
        with col3:
            st.metric("LOW", low_count, delta=None)
        with col4:
            st.metric("Risk Score", risk_score, delta=None)
        
        # Graphique de sévérité
        if high_count + med_count + low_count > 0:
            if HAS_MATPLOTLIB:
                fig, ax = plt.subplots(figsize=(8, 4))
                severities = ["HIGH", "MEDIUM", "LOW"]
                counts = [high_count, med_count, low_count]
                colors = ["#dc3545", "#ffc107", "#28a745"]
                bars = ax.bar(severities, counts, color=colors)
                ax.set_ylabel("Nombre de findings")
                ax.set_title("Distribution des sévérités")
                for bar in bars:
                    height = bar.get_height()
                    if height > 0:
                        ax.text(bar.get_x() + bar.get_width()/2., height,
                                f'{int(height)}', ha='center', va='bottom')
                st.pyplot(fig)
            else:
                st.warning("⚠️ matplotlib non installé. Installez-le avec: pip install matplotlib")
        
        # Détails par scanner
        st.subheader("📋 Détails par Scanner")
        scanner_stats = {}
        for scanner_name, scanner_data in scanners_data.items():
            if scanner_name != "_meta" and isinstance(scanner_data, dict):
                issues = scanner_data.get("issues", [])
                if issues:
                    scanner_stats[scanner_name] = len(issues)
        
        if scanner_stats:
            df_scanners = pd.DataFrame({
                "Scanner": list(scanner_stats.keys()),
                "Findings": list(scanner_stats.values())
            })
            st.dataframe(df_scanners, use_container_width=True)
    else:
        st.info("📊 Aucune analyse récente. Effectuez une analyse dans les onglets 'Analyse de Code' ou 'Analyse GitHub' pour voir les statistiques.")

# ============================================
# TAB 6: HISTORIQUE
# ============================================
if active_tab == "hist":
    st.header("Historique des Analyses")
    st.caption("Affichage hierarchique: Date > Type > Severite > Rapport")

    # Chercher les rapports sauvegardes
    repo_root = Path(__file__).resolve().parents[1]
    reports_env = os.environ.get("REPORTS_DIR", "analyses")
    reports_dir = Path(reports_env)
    if not reports_dir.is_absolute():
        reports_dir = repo_root / reports_dir
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        st.error(f"Erreur creation repertoire rapports: {exc}")
        reports_dir = None

    if reports_dir and reports_dir.exists():
        report_files = list(reports_dir.glob("report_*.json"))
        if report_files:
            st.info(f"{len(report_files)} rapport(s) trouve(s) dans {reports_dir}")

            report_entries = []
            for report_path in report_files:
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        report_data = json.load(f)
                except Exception:
                    continue

                report_dt = _parse_report_datetime(report_data, report_path)
                report_type = _infer_report_type(report_data, report_path.name)
                scanners_data = extract_scanners_data(report_data)

                if scanners_data:
                    high_count, med_count, low_count, risk_score = calculate_metrics(scanners_data)
                else:
                    high_count, med_count, low_count, risk_score = 0, 0, 0, 0

                severity_bucket = _severity_bucket(high_count, med_count, low_count)

                report_entries.append({
                    "path": report_path,
                    "name": report_path.name,
                    "data": report_data,
                    "dt": report_dt,
                    "date": report_dt.strftime("%Y-%m-%d"),
                    "time": report_dt.strftime("%H:%M:%S"),
                    "type": report_type,
                    "severity": severity_bucket,
                    "metrics": {
                        "high": high_count,
                        "med": med_count,
                        "low": low_count,
                        "risk": risk_score,
                    },
                    "scanners": scanners_data,
                })

            if not report_entries:
                st.info("Aucun rapport lisible pour l'historique.")
            else:
                groups = {}
                for entry in report_entries:
                    groups.setdefault(entry["date"], {}).setdefault(entry["type"], {}).setdefault(entry["severity"], []).append(entry)

                type_order = ["generation", "code", "github", "unknown"]
                type_labels = {
                    "generation": "Generation IA",
                    "code": "Analyse de Code",
                    "github": "Analyse GitHub",
                    "unknown": "Autre",
                }
                severity_order = ["HIGH", "MEDIUM", "LOW", "NONE"]

                for date_key in sorted(groups.keys(), reverse=True):
                    date_total = sum(len(items) for type_group in groups[date_key].values() for items in type_group.values())
                    with st.expander(f"{date_key} ({date_total})", expanded=False):
                        for type_key in type_order:
                            if type_key not in groups[date_key]:
                                continue
                            type_group = groups[date_key][type_key]
                            type_total = sum(len(items) for items in type_group.values())
                            type_label = type_labels.get(type_key, type_key.title())

                            with st.expander(f"{type_label} ({type_total})", expanded=False):
                                for sev_key in severity_order:
                                    if sev_key not in type_group:
                                        continue
                                    sev_items = type_group[sev_key]
                                    with st.expander(f"Severite {sev_key} ({len(sev_items)})", expanded=False):
                                        for entry in sorted(sev_items, key=lambda e: e["dt"], reverse=True):
                                            title = f"{entry['time']} - {entry['name']}"
                                            with st.expander(title, expanded=False):
                                                st.caption("Analyse deja effectuee. Rapport charge depuis l'historique.")
                                                st.write("**Date:**", entry["dt"].strftime("%Y-%m-%d %H:%M:%S"))
                                                st.write("**Fichier:**", entry["name"])

                                                metadata = entry["data"].get("metadata", {})
                                                if isinstance(metadata, dict) and metadata:
                                                    st.subheader("Metadonnees")
                                                    col1, col2 = st.columns(2)
                                                    with col1:
                                                        st.write("**Source:**", metadata.get("source", "N/A"))
                                                        st.write("**Langage:**", metadata.get("language", "N/A"))
                                                    with col2:
                                                        st.write("**Type:**", metadata.get("type", "N/A"))
                                                        st.write("**Timestamp:**", metadata.get("timestamp", "N/A"))

                                                generation = entry["data"].get("generation")
                                                if isinstance(generation, dict):
                                                    st.subheader("Generation IA")
                                                    gen_meta = generation.get("metadata", {}) if isinstance(generation.get("metadata"), dict) else {}
                                                    gen_desc = gen_meta.get("description")
                                                    gen_lang = gen_meta.get("language") or entry["data"].get("analysis", {}).get("language") or entry["data"].get("language")

                                                    col1, col2, col3, col4 = st.columns(4)
                                                    with col1:
                                                        st.metric("Provider", generation.get("provider", "N/A"))
                                                    with col2:
                                                        st.metric("Modele", generation.get("model", "N/A"))
                                                    with col3:
                                                        st.metric("Tokens", generation.get("tokens_used", 0))
                                                    with col4:
                                                        cost = generation.get("cost_usd", 0) or 0
                                                        st.metric("Cout", f"${cost:.4f}" if cost else "Gratuit")

                                                    if gen_desc:
                                                        st.write("**Description:**", gen_desc)
                                                    if generation.get("timestamp"):
                                                        st.write("**Date generation:**", generation.get("timestamp"))

                                                    with st.expander("Code genere"):
                                                        st.code(generation.get("code", ""), language=gen_lang or "python")

                                                scanners_data = entry["scanners"]
                                                if scanners_data:
                                                    st.subheader("Resume securite")
                                                    col1, col2, col3, col4 = st.columns(4)
                                                    with col1:
                                                        st.metric("HIGH", entry["metrics"]["high"])
                                                    with col2:
                                                        st.metric("MEDIUM", entry["metrics"]["med"])
                                                    with col3:
                                                        st.metric("LOW", entry["metrics"]["low"])
                                                    with col4:
                                                        st.metric("Risk Score", entry["metrics"]["risk"])

                                                    if HAS_MATPLOTLIB:
                                                        fig, ax = plt.subplots(figsize=(6, 3))
                                                        ax.bar(["HIGH", "MEDIUM", "LOW"], [entry["metrics"]["high"], entry["metrics"]["med"], entry["metrics"]["low"]], color=["#dc3545", "#ffc107", "#28a745"])
                                                        ax.set_xlabel("Severite")
                                                        ax.set_ylabel("Nombre")
                                                        ax.set_title("Distribution des severites")
                                                        st.pyplot(fig)

                                                    st.subheader("Findings")
                                                    findings_list = build_findings_list(scanners_data)
                                                    if findings_list:
                                                        df = pd.DataFrame(findings_list)
                                                        st.dataframe(df, use_container_width=True, height=350)
                                                    else:
                                                        st.info("Aucun finding dans ce rapport.")
                                                else:
                                                    st.info("Aucun resultat de scanner dans ce rapport.")

                                                json_str = json.dumps(entry["data"], indent=2, ensure_ascii=False)
                                                st.download_button(
                                                    label="Telecharger JSON",
                                                    data=json_str,
                                                    file_name=entry["name"],
                                                    mime="application/json",
                                                    key=f"dl_{entry['name']}"
                                                )

                                                with st.expander("Rapport brut"):
                                                    st.json(entry["data"])
        else:
            st.info("Aucun rapport trouve. Demarrez l'API avec SAVE_REPORTS=1 pour sauvegarder les analyses.")
    else:
        st.info("Repertoire de rapports indisponible.")

# ============================================
# TAB 7: AIDE
# ============================================
if active_tab == "help":
    st.header("⚙️ Aide et Documentation")
    
    st.subheader("📖 Guide d'utilisation")
    
    st.markdown("""
    ### 🔒 Analyse de Code
    1. Sélectionnez le langage de votre code
    2. Choisissez les scanners à utiliser
    3. Collez votre code dans la zone de texte
    4. Cliquez sur "Analyser" ou "Analyser (Rapide)" pour Python
    
    ### 🐙 Analyse GitHub
    1. Entrez l'URL complète du dépôt GitHub
    2. Sélectionnez les scanners (dans la sidebar)
    3. Cliquez sur "Analyser"
    
    ### 📊 Dashboard
    Visualisez les statistiques de votre dernière analyse avec des graphiques et métriques.
    
    ### 📚 Historique
    Consultez et téléchargez les rapports d'analyses précédentes.
    """)
    
    st.subheader("🔧 Configuration")
    
    st.markdown("""
    - **URL de l'API** : Par défaut `http://localhost:8000`
    - **API Key** : Optionnel, si l'API requiert une authentification
    """)
    
    st.subheader("📡 Endpoints API")
    
    st.code("""
POST /analyze          - Analyse complète de code
POST /analyze-fast     - Analyse rapide (Python uniquement)
POST /analyze-github   - Analyse de dépôt GitHub
POST /export-pdf       - Export PDF
GET  /status           - État des scanners
GET  /docs             - Documentation interactive
    """)
    
    st.subheader("🔗 Liens utiles")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        - [Documentation API](http://localhost:8000/docs)
        - [Bandit](https://bandit.readthedocs.io/)
        - [Semgrep](https://semgrep.dev/)
        """)
    with col2:
        st.markdown("""
        - [Snyk](https://docs.snyk.io/)
        - [GitHub API](https://docs.github.com/en/rest)
        """)


