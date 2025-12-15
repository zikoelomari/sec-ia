import streamlit as st
import requests
import json
import pandas as pd
from pathlib import Path
from typing import Optional, Dict, List
import io
from datetime import datetime

# Imports optionnels pour matplotlib
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
    
    risk_score = high_count * 5 + med_count * 2 + low_count * 1
    
    return high_count, med_count, low_count, risk_score

def display_results(result: dict, analysis_type: str, code_input: str = ""):
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
    findings_list = []
    
    # Bandit findings
    if "bandit" in scanners_data and "bandit" in scanner_filter:
        bandit_data = scanners_data["bandit"]
        if isinstance(bandit_data, dict) and "issues" in bandit_data:
            for issue in bandit_data["issues"]:
                sev = issue.get("severity", "").upper()
                if sev in severity_filter:
                    findings_list.append({
                        "Scanner": "Bandit",
                        "Sévérité": sev,
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
                        "Sévérité": sev if sev in ["HIGH", "MEDIUM", "LOW"] else "MEDIUM",
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
                        "Sévérité": sev,
                        "Type": issue.get("id", ""),
                        "Message": issue.get("title", "")[:100],
                        "Ligne": "",
                    })
    
    # Detector findings
    if ("gemini_detector" in scanners_data or "gemini_detector_snippet" in scanners_data) and "gemini_detector" in scanner_filter:
        detector_data = scanners_data.get("gemini_detector_snippet") or scanners_data.get("gemini_detector", {})
        if isinstance(detector_data, dict) and "patterns" in detector_data:
            patterns = detector_data["patterns"]
            for pattern_name, count in patterns.items():
                if count > 0 and "MEDIUM" in severity_filter:
                    findings_list.append({
                        "Scanner": "Detector",
                        "Sévérité": "MEDIUM",
                        "Type": pattern_name,
                        "Message": f"Pattern détecté {count} fois",
                        "Ligne": "",
                    })
    
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

api_status = check_api_status()
if api_status:
    st.sidebar.success("✅ API connectée")
else:
    st.sidebar.error("❌ API non accessible")

# Options scanners globales
st.sidebar.markdown("### Options de scan par défaut")
default_scanners = {
    "bandit": st.sidebar.checkbox("Bandit", value=True, key="default_bandit"),
    "semgrep": st.sidebar.checkbox("Semgrep", value=False, key="default_semgrep"),
    "snyk": st.sidebar.checkbox("Snyk", value=False, key="default_snyk"),
    "gemini_detector": st.sidebar.checkbox("Gemini Detector", value=True, key="default_detector"),
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
tab_gen, tab_code, tab_github, tab_compare, tab_dash, tab_hist, tab_help = st.tabs([
    "🤖 Génération IA",
    "📝 Analyse de Code",
    "🐙 Analyse GitHub",
    "📊 Comparaison Providers",
    "📈 Dashboard",
    "📚 Historique",
    "⚙️ Aide"
])

# ============================================
# TAB 1: GÉNÉRATION IA
# ============================================
with tab_gen:
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
                    st.warning("⚠️ OpenAI non configuré (set OPENAI_API_KEY)")
            with col_anthropic:
                if providers_data.get("anthropic_configured"):
                    st.success("✅ Anthropic configuré")
                else:
                    st.warning("⚠️ Anthropic non configuré (set ANTHROPIC_API_KEY)")
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
    
    # Sélection des scanners
    st.subheader("Scanners à exécuter")
    scanners_options = ["bandit", "semgrep", "snyk", "gemini_detector"]
    selected_scanners = st.multiselect(
        "Choisissez les scanners",
        scanners_options,
        default=["bandit", "semgrep", "gemini_detector"] if language == "python" else ["semgrep", "gemini_detector"],
        key="gen_scanners"
    )
    
    # Bouton de génération
    if st.button("🚀 Générer et Analyser", type="primary", use_container_width=True, key="gen_analyze_btn"):
        if not description:
            st.error("Veuillez saisir une description du code à générer")
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
                        generation = result.get("generation", {})
                        analysis = result.get("analysis", {})
                        
                        # Afficher le code généré
                        st.success(f"✅ Code généré avec succès ({generation.get('provider')} - {generation.get('model')})")
                        
                        # Métadonnées de génération
                        col_tokens, col_cost, col_time = st.columns(3)
                        with col_tokens:
                            st.metric("Tokens utilisés", generation.get("tokens_used", 0))
                        with col_cost:
                            cost = generation.get("cost_usd", 0)
                            st.metric("Coût estimé", f"${cost:.4f}" if cost else "Gratuit")
                        with col_time:
                            duration = generation.get("metadata", {}).get("duration_seconds", 0)
                            st.metric("Durée", f"{duration:.2f}s" if duration else "N/A")
                        
                        # Code généré
                        st.subheader("📄 Code généré")
                        st.code(generation.get("code", ""), language=language)
                        
                        # Résultats de l'analyse
                        st.subheader("🔍 Résultats de l'analyse de sécurité")
                        scanners_data = analysis.get("scanners", {})
                        
                        # Calculer les métriques
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
                        
                        # Détails des scanners
                        for scanner_name, scanner_result in scanners_data.items():
                            if isinstance(scanner_result, dict) and scanner_result.get("success"):
                                with st.expander(f"🔎 {scanner_name.upper()}", expanded=False):
                                    issues = scanner_result.get("issues", [])
                                    if issues:
                                        st.write(f"**{len(issues)} issue(s) détecté(s)**")
                                        for issue in issues[:10]:  # Limite 10
                                            severity = issue.get("severity", "UNKNOWN")
                                            message = issue.get("message", issue.get("title", "N/A"))
                                            st.write(f"- [{severity}] {message}")
                                    else:
                                        st.success("Aucune issue détectée")
                    
                    elif response.status_code == 429:
                        st.error("⚠️ Rate limit dépassé. Attendez quelques secondes.")
                    else:
                        st.error(f"Erreur API : {response.status_code} - {response.text}")
                
                except requests.exceptions.Timeout:
                    st.error("⏱️ Timeout : la génération a pris trop de temps (>60s)")
                except Exception as e:
                    st.error(f"❌ Erreur : {e}")

# ============================================
# TAB 2: ANALYSE DE CODE
# ============================================
with tab_code:
    st.header("🔒 Analyse de Code en Temps Réel")
    st.markdown("Analysez votre code pour détecter les vulnérabilités de sécurité")
    
    col_lang, col_scan = st.columns([1, 2])
    
    with col_lang:
        language = st.selectbox(
            "Langage",
            ["python", "javascript", "typescript", "java", "csharp"],
            index=0
        )
    
    with col_scan:
        st.markdown("### Scanners")
        scanners = {
            "bandit": st.checkbox("Bandit", value=default_scanners["bandit"], key="code_bandit"),
            "semgrep": st.checkbox("Semgrep", value=default_scanners["semgrep"], key="code_semgrep"),
            "snyk": st.checkbox("Snyk", value=default_scanners["snyk"], key="code_snyk"),
            "gemini_detector": st.checkbox("Gemini Detector", value=default_scanners["gemini_detector"], key="code_detector"),
        }
    
    selected_scanners = [name for name, enabled in scanners.items() if enabled]
    
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
                        st.success("✅ Analyse rapide terminée!")
                    else:
                        st.error(f"❌ Erreur API: {response.status_code}")
                except Exception as e:
                    st.error(f"❌ Erreur: {str(e)}")
    
    # Afficher les résultats de l'analyse de code
    if "last_code_result" in st.session_state and st.session_state.get("last_analysis_type", "").startswith("code"):
        display_results(st.session_state["last_code_result"], "code", code_input)

# ============================================
# TAB 3: ANALYSE GITHUB
# ============================================
with tab_github:
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
    
    # Options de scan pour GitHub
    st.subheader("Options de scan")
    github_scanners = {
        "bandit": st.checkbox("Bandit", value=default_scanners["bandit"], key="gh_bandit"),
        "semgrep": st.checkbox("Semgrep", value=default_scanners["semgrep"], key="gh_semgrep"),
        "snyk": st.checkbox("Snyk", value=default_scanners["snyk"], key="gh_snyk"),
        "gemini_detector": st.checkbox("Gemini Detector", value=default_scanners["gemini_detector"], key="gh_detector"),
    }
    selected_github_scanners = [name for name, enabled in github_scanners.items() if enabled]
    
    # Token GitHub optionnel
    github_token = st.text_input(
        "Token GitHub (optionnel, pour dépôts privés)",
        type="password",
        help="Personal Access Token pour accéder aux dépôts privés"
    )
    
    if analyze_github_btn:
        if not repo_url.strip():
            st.error("❌ Veuillez entrer une URL GitHub")
        else:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            try:
                status_text.text("🔄 Téléchargement du dépôt...")
                progress_bar.progress(20)
                
                headers = {"Content-Type": "application/json"}
                if API_KEY:
                    headers["X-API-KEY"] = API_KEY
                
                body = {
                    "url": repo_url.strip(),
                    "scanners": selected_github_scanners if selected_github_scanners else None,
                }
                if github_token:
                    body["token"] = github_token
                
                status_text.text("🔄 Analyse en cours... (cela peut prendre plusieurs minutes)")
                progress_bar.progress(40)
                
                response = requests.post(
                    f"{API_BASE_URL}/analyze-github",
                    json=body,
                    headers=headers,
                    timeout=300  # 5 minutes pour les gros dépôts
                )
                
                progress_bar.progress(80)
                
                if response.status_code == 200:
                    result = response.json()
                    st.session_state["last_github_result"] = result
                    st.session_state["last_analysis_type"] = "github"
                    progress_bar.progress(100)
                    status_text.text("✅ Analyse terminée!")
                    st.success(f"✅ Dépôt analysé: {result.get('repo', 'N/A')}")
                else:
                    progress_bar.empty()
                    error_msg = f"Erreur {response.status_code}"
                    try:
                        error_data = response.json()
                        error_msg += f": {error_data.get('detail', response.text)}"
                    except:
                        error_msg += f": {response.text}"
                    st.error(f"❌ {error_msg}")
                    status_text.empty()
                    
            except requests.exceptions.Timeout:
                progress_bar.empty()
                status_text.empty()
                st.error("⏱️ Timeout: L'analyse prend trop de temps. Essayez avec moins de scanners.")
            except Exception as e:
                progress_bar.empty()
                status_text.empty()
                st.error(f"❌ Erreur: {str(e)}")
    
    # Afficher les résultats GitHub
    if "last_github_result" in st.session_state and st.session_state.get("last_analysis_type") == "github":
        display_results(st.session_state["last_github_result"], "github", "")

# ============================================
# TAB 4: COMPARAISON PROVIDERS
# ============================================
with tab_compare:
    st.header("📊 Comparaison des Providers IA")
    st.info("Cette section permet de comparer la sécurité du code généré par différents providers")
    
    # Formulaire de comparaison
    comparison_description = st.text_input(
        "Description du code pour comparaison",
        placeholder="Ex: User authentication system",
        key="compare_desc"
    )
    
    comparison_language = st.selectbox(
        "Langage",
        ["python", "javascript", "typescript", "java", "csharp"],
        key="compare_lang"
    )
    
    if st.button("🔄 Comparer les Providers", type="primary", key="compare_btn"):
        if not comparison_description:
            st.error("Veuillez saisir une description")
        else:
            # Récupérer les providers disponibles
            try:
                providers_resp = requests.get(f"{API_BASE_URL}/api/providers", timeout=5)
                if providers_resp.status_code == 200:
                    providers_data = providers_resp.json()
                    available_providers = providers_data.get("available_providers", ["simulate"])
                else:
                    available_providers = ["simulate"]
            except:
                available_providers = ["simulate"]
            
            results = {}
            
            # Générer avec chaque provider disponible
            for provider in available_providers:
                with st.spinner(f"Génération avec {provider}..."):
                    try:
                        headers = {}
                        if API_KEY:
                            headers["X-API-KEY"] = API_KEY
                        
                        payload = {
                            "description": comparison_description,
                            "language": comparison_language,
                            "provider": provider,
                            "scanners": ["bandit", "semgrep", "gemini_detector"],
                        }
                        
                        response = requests.post(
                            f"{API_BASE_URL}/generate-and-analyze",
                            json=payload,
                            headers=headers,
                            timeout=60
                        )
                        
                        if response.status_code == 200:
                            results[provider] = response.json()
                    except Exception as e:
                        st.warning(f"Échec {provider}: {e}")
            
            # Afficher la comparaison
            if results:
                st.success(f"✅ Comparaison de {len(results)} provider(s) complétée")
                
                # Tableau comparatif
                comparison_data = []
                for provider, result in results.items():
                    gen = result.get("generation", {})
                    analysis = result.get("analysis", {})
                    high, med, low, score = calculate_metrics(analysis.get("scanners", {}))
                    
                    comparison_data.append({
                        "Provider": provider.upper(),
                        "Modèle": gen.get("model", "N/A"),
                        "Tokens": gen.get("tokens_used", 0),
                        "Coût ($)": f"{gen.get('cost_usd', 0):.4f}",
                        "HIGH": high,
                        "MEDIUM": med,
                        "LOW": low,
                        "Risk Score": score,
                    })
                
                df = pd.DataFrame(comparison_data)
                st.dataframe(df, use_container_width=True)
                
                # Graphique comparatif
                if HAS_MATPLOTLIB:
                    fig, ax = plt.subplots(figsize=(10, 5))
                    providers_names = [r["Provider"] for r in comparison_data]
                    risk_scores = [r["Risk Score"] for r in comparison_data]
                    
                    ax.bar(providers_names, risk_scores, color=['#667eea', '#764ba2', '#f093fb'][:len(providers_names)])
                    ax.set_xlabel("Provider")
                    ax.set_ylabel("Risk Score")
                    ax.set_title("Comparaison des Risk Scores par Provider")
                    st.pyplot(fig)
            else:
                st.error("Aucun provider n'a réussi à générer du code")

# TAB 5: DASHBOARD
# ============================================
with tab_dash:
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
with tab_hist:
    st.header("📚 Historique des Analyses")
    
    # Chercher les rapports sauvegardés
    reports_dir = Path("analyses")
    if reports_dir.exists():
        report_files = list(reports_dir.glob("report_*.json"))
        if report_files:
            st.info(f"📁 {len(report_files)} rapport(s) trouvé(s) dans `analyses/`")
            
            # Sélectionner un rapport
            report_options = {f.name: f for f in sorted(report_files, key=lambda x: x.stat().st_mtime, reverse=True)}
            selected_report = st.selectbox(
                "Sélectionner un rapport",
                options=list(report_options.keys()),
                index=0 if report_options else None
            )
            
            if selected_report:
                report_path = report_options[selected_report]
                try:
                    with open(report_path, 'r', encoding='utf-8') as f:
                        report_data = json.load(f)
                    
                    st.subheader(f"📄 Rapport: {selected_report}")
                    
                    # Métadonnées
                    metadata = report_data.get("metadata", {})
                    if metadata:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.write("**Source:**", metadata.get("source", "N/A"))
                            st.write("**Langage:**", metadata.get("language", "N/A"))
                        with col2:
                            st.write("**Type:**", metadata.get("type", "N/A"))
                            st.write("**Date:**", metadata.get("timestamp", "N/A"))
                    
                    # Résumé
                    summary = report_data.get("summary", {})
                    if summary:
                        severity = summary.get("severity", {})
                        risk_score = summary.get("risk_score", 0)
                        
                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("HIGH", severity.get("HIGH", 0))
                        with col2:
                            st.metric("MEDIUM", severity.get("MEDIUM", 0))
                        with col3:
                            st.metric("LOW", severity.get("LOW", 0))
                        with col4:
                            st.metric("Risk Score", risk_score)
                    
                    # Export
                    col_exp1, col_exp2 = st.columns(2)
                    with col_exp1:
                        json_str = json.dumps(report_data, indent=2, ensure_ascii=False)
                        st.download_button(
                            label="📄 Télécharger JSON",
                            data=json_str,
                            file_name=selected_report,
                            mime="application/json"
                        )
                    
                except Exception as e:
                    st.error(f"Erreur lors du chargement du rapport: {str(e)}")
        else:
            st.info("📭 Aucun rapport trouvé. Les analyses seront sauvegardées ici si `SAVE_REPORTS=1` est configuré.")
    else:
        st.info("📁 Le répertoire `analyses/` n'existe pas encore.")

# ============================================
# TAB 7: AIDE
# ============================================
with tab_help:
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
    2. Sélectionnez les scanners
    3. (Optionnel) Ajoutez un token GitHub pour les dépôts privés
    4. Cliquez sur "Analyser"
    
    ### 📊 Dashboard
    Visualisez les statistiques de votre dernière analyse avec des graphiques et métriques.
    
    ### 📚 Historique
    Consultez et téléchargez les rapports d'analyses précédentes.
    """)
    
    st.subheader("🔧 Configuration")
    
    st.markdown("""
    - **URL de l'API** : Par défaut `http://localhost:8000`
    - **API Key** : Optionnel, si l'API requiert une authentification
    - **Token GitHub** : Pour analyser des dépôts privés
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


