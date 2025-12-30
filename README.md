# Génération de Code & Sécurité – Projet FdE

Outil de démonstration pour analyser les risques liés au code généré par IA et comparer les résultats avec des dépôts open-source. Le CLI `cli/security_tool.py` (alias compatible `security_tool.py`) orchestre la génération simulée, l'analyse Bandit/Semgrep/Snyk/CodeQL, la détection de patterns dangereux et la production de rapports (JSON + PDF). Le notebook `analyse_bandit.ipynb` implémente le protocole de quantification avec métriques, visualisations et recommandations. L'interface Streamlit (`frontend_streamlit/`) permet l'analyse en temps réel via l'API FastAPI.

**CI/CD** : Semgrep + CodeQL via GitHub Actions

---

## 🚀 Démarrage Rapide (Start Here!)

```powershell
# 1. Activer l'environnement virtuel
.\.venv\Scripts\Activate.ps1

# 2. Démarrer tous les services avec historique activé
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

**Services démarrés** :
- 🌐 **Backend API** : http://localhost:8000
- 📊 **Interface Streamlit** : http://localhost:8502
- 💾 **Historique** : Sauvegarde automatique activée dans `analyses/`

> **📝 Note importante** : Le script active automatiquement `SAVE_REPORTS=1` pour que toutes vos analyses soient sauvegardées dans l'historique et que le système détecte les analyses déjà effectuées.

[→ Guide détaillé de démarrage](#démarrage-rapide-complet)

---

## Table des matières

1. [Fonctionnalités clés](#fonctionnalités-clés)
2. [Architecture du Projet](#architecture-du-projet) ⭐
3. [Pré-requis](#pré-requis)
4. [Installation](#installation)
5. [Utilisation CLI](#utilisation-cli)
6. [API FastAPI](#api-fastapi)
7. [Interface Streamlit Unifiée](#interface-streamlit-unifiée)
8. [Notebook d'analyse](#notebook-danalyse)
9. [Pipeline GitHub Actions](#pipeline-github-actions)
10. [Compilation et Vérification](#compilation-et-vérification)
11. [Sécurité et Configuration](#sécurité-et-configuration)
12. [Résolution de problèmes](#résolution-de-problèmes)
13. [Guide Complet : Démarrage, Liens GitHub et Tests](#guide-complet--démarrage-liens-github-et-tests) ⭐ NOUVEAU
14. [Ressources complémentaires](#ressources-complémentaires)
15. [Démarrage rapide complet](#démarrage-rapide-complet)

---

## Fonctionnalités clés

- **Génération IA simulée** : `python cli/security_tool.py generate -d "API login" -l python`
- **Analyse de dépôts** : via `git clone` (`analyse-repo`) ou via l'API GitHub (`analyse-github-api`) avec choix de branche et filtre d'extensions (`--branch dev --extensions .py,.js`)
- **Multi-scanners** : Bandit (Python), Semgrep (auto-config multi-langage) et Snyk Code (si la CLI est disponible/authentifiée)
- **Scores de risque & patterns** : résumé HIGH/MED/LOW, score pondéré, détection `assert`, `subprocess`, `exec`, secrets, injections
- **Comparaison IA vs OSS** : `python cli/security_tool.py compare analyses/report_ia.json analyses/report_repo.json`
- **Export PDF** : `python cli/security_tool.py export-pdf analyses/report_xxx.json`
- **Notebook complet** : `analyse_bandit.ipynb` lit tous les `analyses/report_*.json` et produit statistiques, heatmap, recommandations, résumé exécutif
- **Pipeline CI/CD** : `.github/workflows/devsecops_scan.yml` exécute une génération IA, lance Semgrep et publie les artefacts `analyses/`

---

## Architecture du Projet

### Vue d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                    COUCHE PRÉSENTATION                       │
├─────────────────────────────────────────────────────────────┤
│  Landing Page         Dashboard Streamlit       CLI         │
│  (Bootstrap 5)        (app_unified.py)      (security_tool) │
│  :8000/               :8502/                                │
│  • Présentation       • Génération IA          • generate   │
│  • Documentation      • Analyse code           • analyse    │
│                       • GitHub scan            • compare    │
│                       • Comparaison providers  • campaign   │
└────────────┬──────────────────┬─────────────────┬───────────┘
             │                  │                 │
             └──────────────────┴─────────────────┘
                                │
┌────────────────────────────────┼────────────────────────────┐
│                         COUCHE API                           │
├────────────────────────────────┼────────────────────────────┤
│              FastAPI Backend (main.py) :8000                 │
│                                                              │
│  Endpoints:                                                  │
│  • GET  /                  → Landing page                    │
│  • GET  /api/providers     → Providers IA disponibles        │
│  • POST /analyze           → Analyse snippet                 │
│  • POST /analyze-fast      → Analyse rapide (Bandit)         │
│  • POST /analyze-github    → Analyse dépôt GitHub            │
│  • POST /generate-and-analyze → Génération IA + Scan ⭐      │
│                                                              │
│  Middleware: CORS, Rate Limiting, API Key Auth              │
└────────────────────────────────┼────────────────────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────┐
│                      COUCHE LOGIQUE MÉTIER                   │
├────────────────────────────────┼────────────────────────────┤
│  ┌─────────────────────────────▼──────────────────────────┐ │
│  │  Générateurs IA (generators/ai_code_generator.py)      │ │
│  │  • OpenAI GPT-4 / GPT-3.5-turbo                        │ │
│  │  • Anthropic Claude Opus / Sonnet                      │ │
│  │  • Simulation (Templates) - Gratuit                    │ │
│  │  → Auto-détection provider, retry, cost estimation     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Analyseurs (analyzers/)                               │ │
│  │  • Bandit (Python) → JSON output                       │ │
│  │  • Semgrep (multi-langage) → p/python, p/javascript    │ │
│  │  • Snyk Code → snyk code test                          │ │
│  │  • ESLint (JS/TS) → eslint --format json               │ │
│  │  • CodeQL → GitHub Actions                             │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Détecteur Custom (detectors/gemini_detector.py)       │ │
│  │  • AST Parser (Python) → exec, eval, compile           │ │
│  │  • Regex secrets → AWS keys, API tokens, passwords     │ │
│  │  • Subprocess → Popen, shell=True                      │ │
│  └────────────────────────────────────────────────────────┘ │
└────────────────────────────────┼────────────────────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────┐
│                       COUCHE DONNÉES                         │
├────────────────────────────────┼────────────────────────────┤
│  Rapports JSON (analyses/)                                   │
│  • report_<hash>.json      → Rapports individuels            │
│  • campaign_<id>.json      → Agrégat campagne                │
│  • *.pdf                   → Exports PDF (ReportLab)         │
│                                                              │
│  Structure: {metadata, generation, scanners, summary}        │
└──────────────────────────────────────────────────────────────┘
                                 │
┌────────────────────────────────┼────────────────────────────┐
│                    SERVICES EXTERNES                         │
├────────────────────────────────┼────────────────────────────┤
│  OpenAI API          Anthropic API        GitHub API         │
│  • GPT-4             • Claude Opus        • Repo download    │
│  • GPT-3.5-turbo     • Claude Sonnet      • Branch select    │
│  Rate: 3500/min      Rate: 50/min         Rate: 60/h (free)  │
└──────────────────────────────────────────────────────────────┘
```

### Structure des Dossiers

```
sec-ia/
├── backend/                 # API FastAPI & Logique métier
│   ├── main.py             # Endpoints REST
│   ├── analyzers/          # Scanners (Bandit, Semgrep, Snyk)
│   ├── generators/         # Générateurs IA (OpenAI, Anthropic) ⭐
│   ├── detectors/          # Détecteur custom (AST, regex)
│   └── tests/              # Tests unitaires (pytest)
│
├── cli/                    # Interface ligne de commande
│   └── security_tool.py    # generate, analyse, compare, campaign
│
├── frontend_streamlit/     # Interface web interactive
│   └── app_unified.py      # Dashboard Streamlit
│
├── static/                 # Landing page ⭐
│   └── index.html          # Page d'accueil Bootstrap 5
│
├── docs/                   # Documentation ⭐
│   └── SECURITY_FRAMEWORK.md # Framework bonnes pratiques
│
├── notebooks/              # Jupyter notebooks
│   ├── analyse_bandit.ipynb          # Analyse agrégée
│   └── compare_ai_providers.ipynb    # Comparaison providers ⭐
│
├── analyses/               # Rapports générés (JSON, PDF)
│
├── scripts/                # Scripts utilitaires
│   ├── smoke_test.ps1
│   └── semgrep_docker.ps1
│
└── .github/workflows/      # CI/CD
    └── devsecops_scan.yml  # Pipeline GitHub Actions
```

### Composants Clés

| Composant | Technologie | Description |
|-----------|-------------|-------------|
| **API REST** | FastAPI + Uvicorn | Backend, endpoints d'analyse |
| **Générateurs IA** | OpenAI, Anthropic | Génération code réelle ⭐ |
| **Scanners** | Bandit, Semgrep, Snyk, CodeQL | Analyse multi-outils |
| **Détecteur** | AST + Regex | Patterns custom (secrets, exec) |
| **Frontend** | Streamlit | Dashboard interactif |
| **Landing Page** | Bootstrap 5 | Page d'accueil professionnelle ⭐ |
| **CLI** | Python + Click | Interface terminal |
| **Notebooks** | Jupyter + pandas | Analyse statistique |
| **CI/CD** | GitHub Actions | Pipeline automatisé |

### Flux de Données Principal

```
1. Utilisateur (Streamlit) → Formulaire "Génération IA"
                ↓
2. POST /generate-and-analyze {description, language, provider}
                ↓
3. ai_code_generator.py → Appel API OpenAI/Anthropic ⭐
                ↓
4. Code généré (+ metadata: tokens, coût)
                ↓
5. Multi-scanners (Bandit + Semgrep + Detector)
                ↓
6. Agrégation résultats (HIGH/MEDIUM/LOW + risk_score)
                ↓
7. Retour JSON {generation: {...}, analysis: {...}}
                ↓
8. Affichage Dashboard (code + métriques + vulnérabilités)
```

### Variables d'Environnement

**Configuration IA ⭐**
```bash
OPENAI_API_KEY=sk-...              # Clé OpenAI (optionnel)
ANTHROPIC_API_KEY=sk-ant-...       # Clé Anthropic (optionnel)
AI_MODEL=gpt-4                     # Modèle par défaut
AI_TEMPERATURE=0.7                 # Créativité (0.0-1.0)
AI_MAX_TOKENS=500                  # Limite tokens
```

**Configuration API**
```bash
API_KEY=your-secret-key            # Auth API (optionnel)
RATE_LIMIT_PER_MIN=60              # Limite requêtes/min
GITHUB_TOKEN=ghp_...               # Token GitHub (5000 req/h)
```

**Configuration Scanners**
```bash
FORCE_SEMGREP=1                    # Forcer Semgrep (Windows)
SEMGREP_CONFIG_PY=p/python         # Config Semgrep
SCANNER_TIMEOUT_SECONDS=120        # Timeout scanners
```

---

## Pré-requis

- Python 3.13.9 (version cible du projet). Des versions 3.13.x voisines peuvent fonctionner, mais une version inférieure pourra bloquer l'installation de certaines roues (semgrep/reportlab)
- Git (pour `analyse-repo`)
- Accès internet pour l'API GitHub / l'installation des scanners
- (Optionnel) `SNYK_TOKEN` exporté pour pouvoir exécuter `snyk code test`

---

## Installation

### Installation rapide

**Unix/macOS** :
```bash
chmod +x install.sh
./install.sh
source .venv/bin/activate
```

**Windows PowerShell** :
```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
.\.venv\Scripts\Activate.ps1
```

Les scripts installent les dépendances Python (`requirements.txt`, `semgrep`, `reportlab`). Si `pip install semgrep` ou `pip install reportlab` échouent (Python 3.15 ou absence d'outils de build), installez les versions compatibles ou utilisez les binaires officiels. Installez Snyk via `npm install -g snyk` puis `snyk auth` si vous souhaitez activer cette étape.

### Dépendances

**Installation des dépendances** :
```bash
pip install -r requirements.txt
```

Toutes les dépendances (Backend, Frontend Streamlit, Notebook) sont incluses dans un seul fichier `requirements.txt`.

---

## Utilisation CLI

### Commandes de base

```bash
# Générer un snippet IA et le scanner
python cli/security_tool.py generate -d "Client CRUD API" -l python

# Cloner puis analyser un dépôt public
python cli/security_tool.py analyse-repo https://github.com/psf/requests

# Télécharger via API GitHub en ne gardant que les .py et .js d'une branche donnée
python cli/security_tool.py analyse-github-api https://github.com/ORG/REPO --branch develop --extensions .py,.js

# Comparer un rapport IA face à un rapport OSS
python cli/security_tool.py compare analyses/report_1234abcd.json analyses/report_repo_deadbeef.json

# Exporter un rapport en PDF
python cli/security_tool.py export-pdf analyses/report_1234abcd.json
```

### Campagne de prompts (quantification du risque)

Préparez un fichier `prompts.txt` (une description par ligne) ou `prompts.json` (liste de chaînes ou d'objets `{"description": "...", "language": "python"}`). Utilisez le fichier de référence `prompts/prompts_50.json` (50 prompts variés orientés sécurité).

Lancer la campagne avec variabilité probabiliste (3-5 runs par prompt) :

```bash
# Campagne basique
python cli/security_tool.py campaign -p prompts/prompts_50.json -l python --runs-per-prompt 3

# Avec seed pour reproductibilité
python cli/security_tool.py campaign -p prompts/prompts_50.json -l python --runs-per-prompt 3 --seed 42

# Avec un identifiant explicite
python cli/security_tool.py campaign -p prompts/prompts_50.json -l javascript -n poc_copilot --runs-per-prompt 5
```

**Résultats** :
- Rapports individuels : `analyses/campaign_<id>_<index>_run<N>.json` (Bandit + Semgrep si disponible + Snyk si installé)
- Agrégat : `analyses/campaign_<id>.json` avec totaux HIGH/MEDIUM/LOW, moyenne et écart-type des risk_scores

Les rapports JSON sont stockés dans `analyses/report_<token>.json` (avec métadonnées, résultats bruts et résumé). Le PDF nécessite ReportLab + Pillow.

---

## API FastAPI

### Démarrer l'API

```bash
# Activer l'environnement virtuel
. .venv/bin/activate  # Linux/macOS
# ou
. .venv/Scripts/Activate.ps1  # Windows PowerShell

# Démarrer le serveur
python -m uvicorn backend.main:app --reload --port 8000
```

L'API sera accessible sur `http://localhost:8000`. Documentation interactive : `http://localhost:8000/docs`

### Endpoints principaux

- `POST /analyze` : Analyse complète multi-langage pour snippets (scanners optionnels)
- `POST /analyze-fast` : Analyse rapide (Bandit + detector uniquement, Python)
- `POST /analyze-github` : Analyse d'un dépôt GitHub (résolution automatique de branche)
- `POST /export-pdf` : Export d'un rapport d'analyse en PDF
- `GET /status` : État des scanners disponibles
- `GET /api` : Informations sur l'API

### Paramètres

- `scanners` (query ou body) : Liste de scanners à exécuter (`bandit`, `semgrep`, `snyk`, `eslint`, `codeql`, `gemini_detector`)
- Par défaut : Bandit+detector pour Python, Semgrep+detector pour autres langages

### Sécurité

- Clé API via header `X-API-KEY` si `API_KEY` défini dans l'environnement
- Rate-limit : `RATE_LIMIT_PER_MIN` (défaut: 60 requêtes/minute)
- CORS restreint : `ALLOWED_ORIGINS` (défaut: localhost:3000, 8501, 8502, 8000)

### Limites

- Taille max archive : `MAX_REPO_ZIP_BYTES` (défaut: 50MB)
- Taille max extraction : `MAX_REPO_EXTRACT_BYTES` (défaut: 200MB)
- Timeout requests : 10-30s selon l'endpoint

### Persistence

Définir `SAVE_REPORTS=1` et `REPORTS_DIR=analyses` pour conserver chaque réponse API au format JSON.

### Semgrep multi-langage

- Config par défaut : `auto`
- Surcharge via env : `SEMGREP_CONFIG_PY/JS/TS/JAVA/CS` ou `SEMGREP_CONFIG_DEFAULT`

---

## Interface Streamlit Unifiée

### Vue d'ensemble

L'interface unifiée (`frontend_streamlit/app_unified.py`) combine **toutes les fonctionnalités** en une seule application Streamlit interactive avec des onglets organisés.

### Lancement

**Méthode 1 : Directement**
```bash
streamlit run frontend_streamlit/app_unified.py --server.port 8502
```

**Méthode 2 : Via le script de démarrage (recommandé)**
```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1
```

L'interface sera accessible sur `http://localhost:8502`

### Structure de l'Interface (5 onglets)

#### 📝 Onglet "Analyse de Code"
- **Zone de code** : Coller votre code à analyser
- **Sélecteur de langage** : Python, JavaScript, TypeScript, Java, C#
- **Options scanners** : Bandit, Semgrep, Snyk, Gemini Detector
- **Deux modes d'analyse** :
  - **Analyse complète** : Tous les scanners sélectionnés
  - **Analyse rapide** : Bandit + Detector uniquement (Python)
- **Résultats** : Tableaux, filtres, recommandations, export

#### 🐙 Onglet "Analyse GitHub"
- **Champ URL GitHub** : Entrer l'URL du dépôt
- **Token GitHub** : Optionnel pour dépôts privés
- **Sélection scanners** : Identique à l'analyse de code
- **Barre de progression** : Suivi en temps réel
- **Résultats** : Format identique à l'analyse de code

#### 📊 Onglet "Dashboard"
- **Statistiques visuelles** : Métriques HIGH/MEDIUM/LOW
- **Graphiques** : Distribution des sévérités (matplotlib)
- **Détails par scanner** : Nombre de findings par scanner
- **Vue d'ensemble** : Résumé de la dernière analyse

#### 📚 Onglet "Historique"
- **Liste des rapports** : Tous les rapports sauvegardés dans `analyses/`
- **Consultation** : Afficher les métadonnées et résultats
- **Téléchargement** : Export JSON des rapports précédents

#### ⚙️ Onglet "Aide"
- **Guide d'utilisation** : Instructions détaillées
- **Configuration** : Explications des paramètres
- **Endpoints API** : Liste des endpoints disponibles
- **Liens utiles** : Documentation externe

### Configuration

- **URL de l'API** : Modifiable dans la sidebar (défaut: `http://localhost:8000`)
- **API Key** : Optionnel, si l'API requiert une clé d'authentification
- **Token GitHub** : Pour analyser des dépôts privés (dans l'onglet GitHub)
- **Options scanners par défaut** : Pré-configuration pour tous les onglets

### Fonctionnalités

✅ **Tout en un seul endroit** : Plus besoin de naviguer entre différentes interfaces
✅ **Cohérence** : Même format de résultats pour code et GitHub
✅ **Interactivité** : Filtres, graphiques, exports intégrés
✅ **Historique** : Accès facile aux analyses précédentes
✅ **Dashboard** : Visualisation des statistiques
✅ **Organisation** : Onglets clairs et intuitifs

### Configuration des Générateurs IA

Le projet supporte **3 providers** de génération de code IA :

#### 1️⃣ OpenAI (GPT-4, GPT-3.5-turbo)

**Configuration Windows (PowerShell) :**
```powershell
$env:OPENAI_API_KEY = "sk-..."
$env:AI_MODEL = "gpt-4"  # ou gpt-3.5-turbo
$env:AI_TEMPERATURE = "0.7"
$env:AI_MAX_TOKENS = "500"
```

**Configuration Linux/macOS (Bash) :**
```bash
export OPENAI_API_KEY="sk-..."
export AI_MODEL="gpt-4"
export AI_TEMPERATURE="0.7"
export AI_MAX_TOKENS="500"
```

**Obtenir une clé API :**
- Créer un compte sur [platform.openai.com](https://platform.openai.com)
- Aller dans **API Keys** → **Create new secret key**
- **Coût** : ~$0.03/1000 tokens (GPT-4) ou ~$0.0015/1000 tokens (GPT-3.5-turbo)

#### 2️⃣ Anthropic Claude

**Configuration Windows (PowerShell) :**
```powershell
$env:ANTHROPIC_API_KEY = "sk-ant-..."
$env:AI_MODEL = "claude-3-5-sonnet-20241022"  # ou claude-3-opus-20240229
$env:AI_TEMPERATURE = "0.7"
$env:AI_MAX_TOKENS = "500"
```

**Configuration Linux/macOS (Bash) :**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export AI_MODEL="claude-3-5-sonnet-20241022"
```

**Obtenir une clé API :**
- Créer un compte sur [console.anthropic.com](https://console.anthropic.com)
- Aller dans **API Keys** → **Create Key**
- **Coût** : ~$0.003/1000 tokens (Claude Sonnet) ou ~$0.015/1000 tokens (Claude Opus)

#### 3️⃣ Simulation (mode par défaut)

Si aucune clé API n'est configurée, le système bascule automatiquement en mode simulation utilisant des templates prédéfinis pour la démonstration.

**Avantages :**
- ✅ Gratuit (aucun coût)
- ✅ Aucune configuration requise
- ✅ Idéal pour tester l'interface et les scanners

**Inconvénients :**
- ⚠️ Code généré basique (templates fixes)
- ⚠️ Ne reflète pas la diversité réelle des outils IA

#### Variables d'environnement complètes

| Variable | Valeur par défaut | Description |
|----------|-------------------|-------------|
| `OPENAI_API_KEY` | Non défini | Clé API OpenAI (commence par `sk-`) |
| `ANTHROPIC_API_KEY` | Non défini | Clé API Anthropic (commence par `sk-ant-`) |
| `AI_MODEL` | `gpt-4` | Modèle à utiliser (gpt-4, gpt-3.5-turbo, claude-3-5-sonnet-20241022, etc.) |
| `AI_TEMPERATURE` | `0.7` | Créativité de la génération (0.0 = déterministe, 1.0 = créatif) |
| `AI_MAX_TOKENS` | `500` | Nombre maximum de tokens par génération |
| `AI_TIMEOUT_SECONDS` | `30` | Timeout pour les appels API (secondes) |

#### Test rapide de configuration

**Vérifier les providers disponibles :**
```bash
python -c "from backend.generators.ai_code_generator import get_available_providers; print(get_available_providers())"
# Résultat attendu (si OpenAI configuré) : ['openai', 'simulate']
```

**Générer du code avec le CLI :**
```bash
# Avec OpenAI (si clé configurée)
python cli/security_tool.py generate -d "API REST with JWT auth" -l python --provider openai

# Avec Anthropic (si clé configurée)
python cli/security_tool.py generate -d "React form validation" -l javascript --provider anthropic

# Avec simulation (toujours disponible)
python cli/security_tool.py generate -d "User login function" -l python --provider simulate
```

**Utiliser l'interface Streamlit :**
1. Démarrer l'API : `python -m uvicorn backend.main:app --reload --port 8000`
2. Démarrer Streamlit : `streamlit run frontend_streamlit/app_unified.py`
3. Ouvrir http://localhost:8502
4. Aller dans l'onglet **🤖 Génération IA**
5. Le système affiche automatiquement les providers configurés (✅ ou ⚠️)

#### Estimation des coûts

Pour une campagne de **50 prompts** (500 tokens/génération en moyenne) :

| Provider | Modèle | Coût total | Coût/prompt |
|----------|--------|------------|-------------|
| OpenAI | GPT-4 | ~$1.50 | ~$0.03 |
| OpenAI | GPT-3.5-turbo | ~$0.075 | ~$0.0015 |
| Anthropic | Claude Opus | ~$0.75 | ~$0.015 |
| Anthropic | Claude Sonnet | ~$0.15 | ~$0.003 |
| Simulation | Templates | Gratuit | $0 |

**Recommandation pour le PFA :**
- **Développement/tests** : Mode simulation (gratuit)
- **Démonstration** : Claude Sonnet (bon rapport coût/qualité, ~$0.15 pour 50 prompts)
- **Recherche approfondie** : GPT-4 ou Claude Opus (meilleure qualité)

#### Sécurité des clés API

⚠️ **IMPORTANT** : Ne jamais commit les clés API dans Git !

**Bonnes pratiques :**
- ✅ Utiliser des variables d'environnement
- ✅ Ajouter `.env` au `.gitignore` (déjà fait)
- ✅ Utiliser des clés séparées pour dev/prod
- ✅ Révoquer immédiatement les clés exposées
- ✅ Définir des limites de dépenses sur les dashboards OpenAI/Anthropic

**Fichier `.env` (optionnel) :**
```env
# .env - Ne jamais commit ce fichier !
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
AI_MODEL=gpt-4
AI_TEMPERATURE=0.7
```

**Charger avec python-dotenv :**
```bash
pip install python-dotenv
python -c "from dotenv import load_dotenv; load_dotenv(); from backend.generators.ai_code_generator import get_available_providers; print(get_available_providers())"
```

#### Dépannage

**Erreur "OPENAI_API_KEY not set" :**
- Vérifier que la variable est définie : `echo $env:OPENAI_API_KEY` (PowerShell)
- Vérifier que le terminal a été redémarré après la définition
- Tester avec `python -c "import os; print(os.environ.get('OPENAI_API_KEY'))"`

**Erreur "Rate limit exceeded" :**
- Attendre 1 minute (limites : 3500 req/min OpenAI, 50 req/min Anthropic tier 1)
- Réduire le nombre de prompts simultanés
- Augmenter le tier du compte API

**Erreur "Invalid API key" :**
- Vérifier que la clé commence par `sk-` (OpenAI) ou `sk-ant-` (Anthropic)
- Régénérer une nouvelle clé sur le dashboard
- Vérifier que le compte API a des crédits

### Utilisation

**Analyser du code** :
1. Onglet "Analyse de Code"
2. Sélectionner le langage
3. Choisir les scanners
4. Coller le code
5. Cliquer sur "Analyser" ou "Analyser (Rapide)"

**Analyser un dépôt GitHub** :
1. Onglet "Analyse GitHub"
2. Entrer l'URL GitHub
3. (Optionnel) Ajouter un token
4. Choisir les scanners
5. Cliquer sur "Analyser"

**Consulter les statistiques** :
1. Onglet "Dashboard"
2. Visualiser les graphiques
3. Consulter les détails par scanner

**Consulter l'historique** :
1. Onglet "Historique"
2. Sélectionner un rapport
3. Consulter ou télécharger

---

## Notebook d'analyse

Le notebook `analyse_bandit.ipynb` implémente le protocole de quantification pour analyser les risques liés au code généré par IA.

### Utilisation

1. Activez l'environnement virtuel et installez les dépendances :
   ```bash
   pip install jupyter matplotlib pandas
   ```

2. Lancez Jupyter :
   ```bash
   jupyter notebook analyse_bandit.ipynb
   ```

3. Le notebook :
   - Charge les prompts de référence depuis `prompts/prompts_50.json`
   - Lit tous les rapports de campagne dans `analyses/`
   - Calcule les métriques (LOC, vulnérabilités / 1k LOC, distribution des sévérités, catégories)
   - Produit des visualisations (bar charts, heatmap IA vs OSS)
   - Génère un résumé exécutif avec top 5 catégories/scanners et recommandations actionnables

### Métriques calculées

- LOC par snippet/run (lignes non vides)
- Vulnérabilités / 1k LOC (global et par scanner)
- Distribution des sévérités HIGH/MEDIUM/LOW
- Catégories (injection, secrets, exec/eval, subprocess, crypto, auth, deserialization, etc.)
- Score moyen et écart-type (risk_score)

### Visualisations

- Bar chart des sévérités
- Bar chart vuln/1kLOC par catégorie
- Bar chart vuln/1kLOC par scanner
- Heatmap simple IA vs OSS (si rapports disponibles)

---

## Pipeline GitHub Actions

Le workflow `.github/workflows/devsecops_scan.yml` :

1. Configure Python 3.13.9
2. Installe les dépendances (`pip install -r requirements.txt`, `semgrep`, `reportlab`)
3. **Initialise CodeQL** pour Python et JavaScript (queries: security-extended, security-and-quality)
4. Exécute `python cli/security_tool.py generate ...` pour générer un échantillon de code IA
5. Lance **Semgrep** avec config auto
6. **Exécute l'analyse CodeQL**
7. Exporte le dernier rapport en PDF
8. Publie le dossier `analyses/` comme artefact

**Scanners CI** : Semgrep + CodeQL (les deux sont exécutés en parallèle)

**Permissions requises** :
- `security-events: write` (pour CodeQL)
- `actions: read`
- `contents: read`

> **Badge CI** : Le workflow est configuré pour s'exécuter sur push/PR vers `main` et `develop`, ainsi que manuellement via `workflow_dispatch`.

> **Secrets recommandés** : `SNYK_TOKEN` (facultatif). Le workflow installe Snyk uniquement si la variable est définie. Pensez également à définir `GITHUB_TOKEN` ou un token personnel pour augmenter les limites API lors de `analyse-github-api`.

---

## Compilation et Vérification

### Méthode 1 : Script Automatique (Recommandé)

**Windows (PowerShell)** :
```powershell
powershell -ExecutionPolicy Bypass -File scripts/compile_check.ps1
```

**Linux/macOS (Bash)** :
```bash
chmod +x scripts/compile_check.sh
./scripts/compile_check.sh
```

### Méthode 2 : Compilation Manuelle

**Vérifier tous les fichiers Python** :
```bash
python -m py_compile cli/security_tool.py
python -m py_compile backend/main.py
python -m py_compile frontend_streamlit/app_unified.py
python -m py_compile backend/analyzers/bandit_analyzer.py
python -m py_compile backend/analyzers/multi_analyzer.py
python -m py_compile backend/detectors/gemini_detector.py
```

**Vérifier les imports** :
```bash
# CLI
python -c "import sys; sys.path.insert(0, '.'); from cli.security_tool import build_parser; print('CLI OK')"

# API
python -c "import sys; sys.path.insert(0, '.'); from backend.main import app; print('API OK')"
```

**Vérifier le JSON** :
```bash
python -c "import json; f=open('prompts/prompts_50.json','r',encoding='utf-8'); d=json.load(f); f.close(); print(f'JSON valide: {len(d)} prompts')"
```

### Méthode 3 : Compilation Complète

**Windows** :
```powershell
powershell -ExecutionPolicy Bypass -File scripts/compile_all.ps1
```

### Checklist de Compilation

Avant de considérer le projet comme "compilé", vérifiez :

- [ ] Tous les fichiers Python compilent sans erreur (`py_compile`)
- [ ] Les imports CLI fonctionnent (`from cli.security_tool import build_parser`)
- [ ] Les imports API fonctionnent (`from backend.main import app`)
- [ ] Le fichier JSON des prompts est valide
- [ ] Le workflow GitHub Actions est présent
- [ ] Le notebook est présent
- [ ] Les requirements.txt sont présents

### Vérification Rapide

```bash
# Windows
python -m py_compile cli/security_tool.py backend/main.py frontend_streamlit/app_unified.py

# Linux/macOS
python3 -m py_compile cli/security_tool.py backend/main.py frontend_streamlit/app_unified.py
```

Si aucune erreur n'apparaît, les fichiers principaux sont syntaxiquement corrects.

---

## Sécurité et Configuration

### Configuration API (Optionnelle)

**English — Quick start** :
- Configure (optional): set an API key and rate limit in your shell:

```powershell
# Example (PowerShell):
$env:API_KEY = 'your-test-key'
$env:RATE_LIMIT_PER_MIN = '60'
```

- Start the server (activate your venv first):

```powershell
. .\.venv\Scripts\Activate.ps1
python -m uvicorn backend.main:app --reload --port 8000
```

- Behavior:
  - If `API_KEY` is set, requests must include `X-API-KEY` header with that value.
  - `RATE_LIMIT_PER_MIN` controls allowed requests per minute per key (default `60`).
  - The implementation uses a simple in-memory limiter (per-process). For production replace with Redis or another shared store.

**Français — Démarrage rapide** :
- Configuration (optionnelle) : définissez une clé API et le quota dans votre session PowerShell :

```powershell
# Exemple :
$env:API_KEY = 'ma-cle-de-test'
$env:RATE_LIMIT_PER_MIN = '60'
```

- Démarrer le serveur (activez le venv) :

```powershell
. .\.venv\Scripts\Activate.ps1
python -m uvicorn backend.main:app --reload --port 8000
```

- Comportement :
  - Si `API_KEY` est défini, il doit être envoyé dans l'en-tête `X-API-KEY` pour les requêtes.
  - `RATE_LIMIT_PER_MIN` définit le nombre de requêtes autorisées par minute par clé (par défaut `60`).
  - Le limiteur actuel est en mémoire (par processus). En production, utilisez Redis ou un store partagé pour une limitation fiable entre réplicas.

### Notes de sécurité & recommandations

- Do not expose the scanning endpoints publicly without authentication and quotas. The scanners spawn subprocesses and may be resource-intensive.
- For production readiness:
  - Use `API_KEY` (or OAuth) behind TLS.
  - Replace the in-memory rate limiter with Redis (or a managed rate-limiting service).
  - Run scanners in an isolated worker pool or task queue (Celery/RQ) with resource/time limits (cgroups, containers).
  - Limit archive extraction sizes via `MAX_REPO_ZIP_BYTES` and `MAX_REPO_EXTRACT_BYTES` environment variables (already supported in `backend/main.py`).

---

## Résolution de problèmes

### Erreur "No module named 'X'"
```bash
pip install X
```

### Erreur de compilation Python
Vérifiez la version Python (requis: 3.13.x) :
```bash
python --version
```

### Erreur JSON
Vérifiez la syntaxe JSON :
```bash
python -m json.tool prompts/prompts_50.json
```

### Problèmes Semgrep sur Windows

Sur Windows, Semgrep peut rencontrer des problèmes d'encodage liés à la locale (cp1252). Si vous obtenez des erreurs `UnicodeEncodeError` lors de l'exécution de Semgrep depuis l'API, l'API gère automatiquement ces cas. Pour forcer Semgrep, définissez `FORCE_SEMGREP=1` avec `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8`.

#### Exécuter Semgrep sur Windows (conseil)

Sur Windows, Semgrep peut rencontrer des problèmes d'encodage liés à la locale (cp1252). Si vous obtenez des erreurs `UnicodeEncodeError` lors de l'exécution de Semgrep depuis l'API, utilisez le conteneur Docker officiel pour exécuter Semgrep de façon reproductible.

**PowerShell (script fourni) :**

```powershell
# Lancer semgrep via Docker pour analyser le répertoire courant
.\scripts\semgrep_docker.ps1 -Path . -Config auto

# Ou avec des options personnalisées
.\scripts\semgrep_docker.ps1 -Path ./backend -Config p/python -OutputFile backend_scan.json
```

Le script `scripts/semgrep_docker.ps1` monte le répertoire courant en lecture seule dans le conteneur `returntocorp/semgrep` et produit la sortie JSON standard. Cette méthode évite les problèmes d'encodage sur Windows et est recommandée pour des scans reproductibles.

### Limitations connues

- `pip install semgrep` et `pip install reportlab` peuvent échouer si les roues 3.13.x ne sont pas disponibles (ou sous Windows en l'absence d'outils de build). Dans ce cas, installez Python 3.13.9 ou utilisez les binaires Semgrep/Snyk fournis par les éditeurs.
- L'API GitHub est limitée à 60 requêtes/heure sans token. Configurez `GITHUB_TOKEN` dans votre environnement pour éviter les erreurs 403 (rate limit).
- `snyk code test` nécessite `snyk auth`. Sans cela, l'appel sera ignoré mais les autres scanners continueront.
- Les rapports `analyses/` peuvent contenir des données sensibles (nom du dépôt, chemins). Nettoyez-les avant de les publier.

### Notes importantes

- En Python, la "compilation" vérifie uniquement la syntaxe, pas la logique
- Les erreurs d'import peuvent survenir si les dépendances ne sont pas installées
- Le notebook Jupyter nécessite `jupyter`, `matplotlib` et `pandas` pour fonctionner complètement
- Les scanners externes (Bandit, Semgrep, Snyk) doivent être installés séparément

---

## Ressources complémentaires

- [Semgrep docs](https://semgrep.dev/docs/)
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-the-snyk-cli)
- [Bandit](https://bandit.readthedocs.io/)
- [GitHub REST API v3](https://docs.github.com/en/rest)
- [CodeQL](https://codeql.github.com/docs/)
- [Streamlit](https://docs.streamlit.io/)

---

## Guide Complet : Démarrage, Liens GitHub et Tests

### 📋 Table des matières du guide

1. [Démarrer l'application](#1-démarrer-lapplication)
2. [Ajouter des liens GitHub](#2-ajouter-des-liens-github)
3. [Créer et exécuter des tests](#3-créer-et-exécuter-des-tests)
4. [Checklist complète](#4-checklist-complète)
5. [Commandes rapides](#5-commandes-rapides)

---

### 1. Démarrer l'application

#### Méthode 1 : Script automatique (recommandé)

```powershell
# 1. Installation initiale (une seule fois)
powershell -ExecutionPolicy Bypass -File install.ps1

# 2. Démarrer tous les services
powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1
```

Cela démarre automatiquement :
- **Backend API** : `http://localhost:8000`
- **Landing Page** : `http://localhost:8000/`
- **Streamlit Dashboard** : `http://localhost:8502`

#### Méthode 2 : Démarrage manuel

```powershell
# Activer l'environnement virtuel
.\.venv\Scripts\Activate.ps1

# Terminal 1 : Backend API
python -m uvicorn backend.main:app --reload --port 8000

# Terminal 2 : Streamlit (dans un autre terminal)
cd frontend_streamlit
streamlit run app_unified.py --server.port 8502
```

#### Vérification que tout fonctionne

Une fois démarré, vérifiez que les services sont accessibles :

- ✅ **Backend API** : `http://localhost:8000/api`
- ✅ **API Documentation** : `http://localhost:8000/docs`
- ✅ **Landing Page** : `http://localhost:8000/`
- ✅ **Streamlit Dashboard** : `http://localhost:8502`

---

### 2. Ajouter des liens GitHub

#### A. Modifier la landing page (`static/index.html`)

**Étape 1** : Remplacez `https://github.com/votre-repo` par votre URL GitHub réelle.

**Ligne 349-351** (Section CTA) :
```html
<a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" class="btn btn-outline-light btn-lg">
    <i class="bi bi-github"></i> Voir sur GitHub
</a>
```

**Ligne 358-362** (Footer) :
```html
<footer class="bg-dark text-white py-4">
    <div class="container text-center">
        <p class="mb-0">
            © 2024 AI Code Security Analysis Platform | 
            Projet PFA | 
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" class="text-white">Documentation</a> | 
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" class="text-white">API</a> |
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" class="text-white">GitHub</a>
        </p>
    </div>
</footer>
```

#### B. Ajouter un badge GitHub dans le Hero

Ajoutez après la ligne 157 (dans la section Hero) :
```html
<a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" target="_blank" class="btn btn-outline-light btn-lg ms-3">
    <i class="bi bi-github"></i> Star sur GitHub
</a>
```

#### C. Ajouter une section "Contribuer" (optionnel)

Ajoutez avant le footer (après la section CTA, ligne ~353) :
```html
<!-- Section Contribuer -->
<section class="py-5 bg-light">
    <div class="container text-center">
        <h2 class="display-5 fw-bold mb-4">Contribuer au Projet</h2>
        <p class="lead mb-4">
            Ce projet est open source. Contribuez, signalez des bugs, ou proposez des améliorations !
        </p>
        <div class="d-flex justify-content-center gap-3">
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO" target="_blank" class="btn btn-dark btn-lg">
                <i class="bi bi-github"></i> Voir le Code Source
            </a>
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO/issues" target="_blank" class="btn btn-outline-dark btn-lg">
                <i class="bi bi-bug"></i> Signaler un Bug
            </a>
            <a href="https://github.com/VOTRE-USERNAME/VOTRE-REPO/pulls" target="_blank" class="btn btn-outline-dark btn-lg">
                <i class="bi bi-code-slash"></i> Proposer une PR
            </a>
        </div>
    </div>
</section>
```

#### D. Ajouter des liens dans Streamlit

Dans `frontend_streamlit/app_unified.py`, ajoutez dans la sidebar (après la ligne 28) :
```python
st.sidebar.markdown("---")
st.sidebar.markdown("### 🔗 Liens Utiles")
st.sidebar.markdown("""
- [📖 Documentation](https://github.com/VOTRE-USERNAME/VOTRE-REPO)
- [🐛 Issues](https://github.com/VOTRE-USERNAME/VOTRE-REPO/issues)
- [⭐ Star](https://github.com/VOTRE-USERNAME/VOTRE-REPO)
- [📝 API Docs](http://localhost:8000/docs)
""")
```

---

### 3. Créer et exécuter des tests

#### Structure actuelle des tests

```
backend/tests/
├── test_ai_generators.py      # Tests générateurs IA
├── test_api_integration.py     # Tests API FastAPI
└── test_main_unit.py           # Tests unitaires backend
```

#### Exécuter tous les tests

```powershell
# Activer l'environnement virtuel
.\.venv\Scripts\Activate.ps1

# Exécuter tous les tests
pytest backend/tests/ -v

# Avec couverture de code
pytest backend/tests/ --cov=backend --cov-report=html

# Tests spécifiques
pytest backend/tests/test_ai_generators.py -v
pytest backend/tests/test_api_integration.py -v
```

#### Créer un nouveau test

**Exemple : Test pour les analyseurs**

Créez `backend/tests/test_analyzers.py` :
```python
"""Tests pour les analyseurs de sécurité."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.analyzers.bandit_analyzer import analyze_python_path_with_bandit
from backend.analyzers.multi_analyzer import run_all_scans_on_path


class TestBanditAnalyzer:
    """Tests pour Bandit."""
    
    def test_bandit_analyzes_python_code(self, tmp_path):
        """Test que Bandit analyse correctement du code Python."""
        # Créer un fichier Python de test
        test_file = tmp_path / "test.py"
        test_file.write_text("import os\nos.system('rm -rf /')  # DANGEROUS")
        
        result = analyze_python_path_with_bandit(test_file)
        
        assert result["success"] is True
        assert "issues" in result
        assert len(result["issues"]) > 0  # Devrait détecter os.system


class TestMultiAnalyzer:
    """Tests pour l'analyseur multi-scanners."""
    
    @patch("backend.analyzers.multi_analyzer.run_semgrep")
    @patch("backend.analyzers.multi_analyzer.analyze_python_path_with_bandit")
    def test_multi_analyzer_runs_all_scanners(self, mock_bandit, mock_semgrep, tmp_path):
        """Test que tous les scanners sont exécutés."""
        test_file = tmp_path / "test.py"
        test_file.write_text("print('hello')")
        
        mock_bandit.return_value = {"success": True, "issues": []}
        mock_semgrep.return_value = {"success": True, "issues": []}
        
        result = run_all_scans_on_path(
            test_file,
            language="python",
            scanners=["bandit", "semgrep"]
        )
        
        assert "bandit" in result
        assert "semgrep" in result
        mock_bandit.assert_called_once()
        mock_semgrep.assert_called_once()
```

#### Test d'intégration API

**Exemple : Test du endpoint `/generate-and-analyze`**

Ajoutez dans `backend/tests/test_api_integration.py` :
```python
import os

def test_generate_and_analyze_endpoint(self):
    """Test l'endpoint de génération + analyse."""
    with patch("backend.main.generate_code_with_ai") as mock_gen:
        mock_gen.return_value = {
            "code": "def test(): pass",
            "model": "gpt-4",
            "provider": "openai",
            "tokens_used": 100,
            "cost_usd": 0.01
        }
        with patch("backend.main.run_all_scans_on_path") as mock_scan:
            mock_scan.return_value = {"bandit": {"success": True, "issues": []}}
            
            resp = self.client.post(
                "/generate-and-analyze",
                json={
                    "description": "A simple function",
                    "language": "python",
                    "provider": "simulate"
                },
                headers={"X-API-KEY": "test-key"} if os.getenv("API_KEY") else {}
            )
            
            assert resp.status_code == 200
            body = resp.json()
            assert "generation" in body
            assert "analysis" in body
            assert body["generation"]["provider"] == "openai"
```

#### Test de bout en bout (E2E)

Créez `backend/tests/test_e2e.py` :
```python
"""Tests end-to-end pour l'application complète."""
import pytest
from fastapi.testclient import TestClient
from backend import main


@pytest.fixture
def client():
    """Client de test pour l'API."""
    return TestClient(main.app)


def test_full_workflow(client):
    """Test le workflow complet : génération → analyse → export."""
    # 1. Générer du code
    gen_resp = client.post(
        "/generate-and-analyze",
        json={
            "description": "A secure login function",
            "language": "python",
            "provider": "simulate"
        }
    )
    assert gen_resp.status_code == 200
    
    # 2. Vérifier les résultats
    data = gen_resp.json()
    assert "generation" in data
    assert "analysis" in data
    
    # 3. Vérifier que le code généré est analysé
    assert "scanners" in data["analysis"]
```

#### Script de test automatisé

Créez `scripts/run_tests.ps1` :
```powershell
# Script pour exécuter tous les tests
Write-Host "=== EXECUTION DES TESTS ===" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

# Activer l'environnement virtuel
if (Test-Path ".venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "[ERREUR] Environnement virtuel introuvable" -ForegroundColor Red
    exit 1
}

Write-Host "`nExécution des tests unitaires..." -ForegroundColor Yellow
pytest backend/tests/ -v --tb=short

Write-Host "`nGénération du rapport de couverture..." -ForegroundColor Yellow
pytest backend/tests/ --cov=backend --cov-report=html --cov-report=term

Write-Host "`nRapport de couverture généré dans: htmlcov/index.html" -ForegroundColor Green
```

**Exécuter les tests** :
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_tests.ps1
```

---

### 4. Checklist complète

#### ✅ Démarrage
- [ ] `install.ps1` exécuté avec succès
- [ ] Environnement virtuel créé (`.venv/`)
- [ ] Dépendances installées (`requirements.txt`)
- [ ] Backend démarre sur `:8000`
- [ ] Streamlit démarre sur `:8502`
- [ ] Landing page accessible sur `:8000/`

#### ✅ Liens GitHub
- [ ] Remplacement de `https://github.com/votre-repo` dans `static/index.html`
- [ ] Liens ajoutés dans le footer
- [ ] Section "Contribuer" ajoutée (optionnel)
- [ ] Liens ajoutés dans Streamlit sidebar (optionnel)

#### ✅ Tests
- [ ] Tests existants passent (`pytest backend/tests/`)
- [ ] Nouveaux tests créés si nécessaire
- [ ] Couverture de code > 70% (optionnel)
- [ ] Script `run_tests.ps1` fonctionne

---

### 5. Commandes rapides

```powershell
# Installation
.\install.ps1

# Démarrage
.\scripts\start_all.ps1

# Tests
pytest backend/tests/ -v

# Tests avec couverture
pytest backend/tests/ --cov=backend --cov-report=html

# Compilation
python -m py_compile backend/main.py cli/security_tool.py

# Vérification API
curl http://localhost:8000/api
```

---

**Note** : Pour plus de détails sur chaque section, consultez les sections dédiées dans ce README :
- [Installation](#installation)
- [API FastAPI](#api-fastapi)
- [Interface Streamlit Unifiée](#interface-streamlit-unifiée)
- [Compilation et Vérification](#compilation-et-vérification)

---

## Démarrage rapide complet

### 🚀 Démarrage du projet (Méthode Recommandée)

**IMPORTANT** : Le script de démarrage active automatiquement la sauvegarde des rapports dans l'historique.

```powershell
# Dans votre terminal principal
cd "C:\Users\zakaria elaou\Desktop\pfa\sec-ia"
.\.venv\Scripts\Activate.ps1

# Lancer tous les services avec historique activé
powershell -ExecutionPolicy Bypass -File scripts\start_all.ps1
```

**Ce que fait le script** :
- ✅ Active `SAVE_REPORTS=1` (sauvegarde automatique)
- ✅ Crée le dossier `analyses/` pour les rapports
- ✅ Démarre le Backend API sur http://localhost:8000
- ✅ Démarre Streamlit sur http://localhost:8502
- ✅ Affiche un message de confirmation : `[ACTIF] Sauvegarde automatique des rapports`

**Après le démarrage** :
1. Ouvrir http://localhost:8502 dans votre navigateur
2. Effectuer une analyse (Code, GitHub, ou Génération IA)
3. Vérifier que le rapport est sauvegardé : `dir analyses\`
4. Refaire la même analyse → Message : "Analyse déjà effectuée"
5. Consulter l'historique dans l'onglet **"Historique"**

---

### 1. Compiler tout le projet
```powershell
powershell -ExecutionPolicy Bypass -File scripts/compile_all.ps1
```

### 2. Démarrer tous les services (Méthode Alternative)
```powershell
powershell -ExecutionPolicy Bypass -File scripts/start_all.ps1
```

Cela démarre :
- **Backend API** : http://localhost:8000
- **Streamlit Unifié** : http://localhost:8502
- **Historique** : Activé automatiquement (analyses/)

### 3. Tester un dépôt GitHub
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test_github.ps1
```

---

**Projet** : Génération de Code & Sécurité – Projet FdE  
**Version** : 1.0  
**CI/CD** : Semgrep + CodeQL via GitHub Actions
