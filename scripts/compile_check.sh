#!/bin/bash
# Script de compilation et vérification du projet (Linux/macOS)

echo "🔍 Vérification de la compilation du projet..."

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

ERRORS=0
WARNINGS=0

# 1. Vérifier les fichiers Python principaux
echo ""
echo "📝 Vérification des fichiers Python..."
PYTHON_FILES=(
    "cli/security_tool.py"
    "backend/main.py"
    "frontend_streamlit/app_unified.py"
    "backend/analyzers/bandit_analyzer.py"
    "backend/analyzers/multi_analyzer.py"
    "backend/detectors/gemini_detector.py"
)

for file in "${PYTHON_FILES[@]}"; do
    if [ -f "$file" ]; then
        if python -m py_compile "$file" 2>/dev/null; then
            echo "  ✅ $file"
        else
            echo "  ❌ $file : erreur de compilation"
            ((ERRORS++))
        fi
    else
        echo "  ⚠️  $file : fichier introuvable"
        ((WARNINGS++))
    fi
done

# 2. Vérifier le JSON des prompts
echo ""
echo "📄 Vérification des fichiers JSON..."
if python -c "import json; json.load(open('prompts/prompts_50.json', 'r', encoding='utf-8'))" 2>/dev/null; then
    COUNT=$(python -c "import json; print(len(json.load(open('prompts/prompts_50.json', 'r', encoding='utf-8'))))")
    echo "  ✅ prompts/prompts_50.json : $COUNT prompts valides"
else
    echo "  ❌ prompts/prompts_50.json : erreur"
    ((ERRORS++))
fi

# 3. Vérifier les imports de la CLI
echo ""
echo "🔗 Vérification des imports CLI..."
if python -c "import sys; sys.path.insert(0, '.'); from cli.security_tool import build_parser" 2>/dev/null; then
    echo "  ✅ CLI imports valides"
else
    echo "  ⚠️  CLI imports : erreur"
    ((WARNINGS++))
fi

# 4. Vérifier les imports de l'API
echo ""
echo "🔗 Vérification des imports API..."
if python -c "import sys; sys.path.insert(0, '.'); from backend.main import app" 2>/dev/null; then
    echo "  ✅ API imports valides"
else
    echo "  ⚠️  API imports : erreur"
    ((WARNINGS++))
fi

# 5. Vérifier le workflow GitHub Actions
echo ""
echo "⚙️  Vérification du workflow GitHub Actions..."
if [ -f ".github/workflows/devsecops_scan.yml" ]; then
    echo "  ✅ Workflow GitHub Actions présent"
else
    echo "  ⚠️  Workflow GitHub Actions introuvable"
    ((WARNINGS++))
fi

# 6. Vérifier le notebook
echo ""
echo "📓 Vérification du notebook..."
if [ -f "analyse_bandit.ipynb" ]; then
    echo "  ✅ Notebook analyse_bandit.ipynb présent"
else
    echo "  ⚠️  Notebook introuvable"
    ((WARNINGS++))
fi

# Résumé
echo ""
echo "============================================================"
echo "📊 RÉSUMÉ DE LA COMPILATION"
echo "============================================================"
echo "  ✅ Fichiers compilés avec succès"
echo "  ⚠️  Avertissements : $WARNINGS"
echo "  ❌ Erreurs : $ERRORS"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "✅ Le projet compile sans erreurs !"
    exit 0
else
    echo "❌ Le projet contient des erreurs de compilation."
    exit 1
fi

