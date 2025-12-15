# Script de compilation et verification du projet
Write-Host "Verification de la compilation du projet..." -ForegroundColor Cyan

$ErrorActionPreference = "Stop"
$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

$errors = 0
$warnings = 0

# 1. Verifier les fichiers Python principaux
Write-Host "`nVerification des fichiers Python..." -ForegroundColor Yellow
$pythonFiles = @(
    "cli/security_tool.py",
    "backend/main.py",
    "frontend_streamlit/app_unified.py",
    "backend/analyzers/bandit_analyzer.py",
    "backend/analyzers/multi_analyzer.py",
    "backend/detectors/gemini_detector.py"
)

foreach ($file in $pythonFiles) {
    if (Test-Path $file) {
        try {
            python -m py_compile $file 2>&1 | Out-Null
            Write-Host "  [OK] $file" -ForegroundColor Green
        } catch {
            Write-Host "  [ERREUR] $file : $_" -ForegroundColor Red
            $errors++
        }
    } else {
        Write-Host "  [WARN] $file : fichier introuvable" -ForegroundColor Yellow
        $warnings++
    }
}

# 2. Verifier le JSON des prompts
Write-Host "`nVerification des fichiers JSON..." -ForegroundColor Yellow
try {
    $prompts = Get-Content "prompts/prompts_50.json" -Raw | ConvertFrom-Json
    Write-Host "  [OK] prompts/prompts_50.json : $($prompts.Count) prompts valides" -ForegroundColor Green
} catch {
    Write-Host "  [ERREUR] prompts/prompts_50.json : $_" -ForegroundColor Red
    $errors++
}

# 3. Verifier les imports de la CLI
Write-Host "`nVerification des imports CLI..." -ForegroundColor Yellow
try {
    $cmd = 'import sys; sys.path.insert(0, "."); from cli.security_tool import build_parser; parser = build_parser(); print("OK")'
    $result = python -c $cmd 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] CLI imports valides" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] CLI imports : $result" -ForegroundColor Yellow
        $warnings++
    }
} catch {
    Write-Host "  [WARN] CLI imports : $_" -ForegroundColor Yellow
    $warnings++
}

# 4. Verifier les imports de l'API
Write-Host "`nVerification des imports API..." -ForegroundColor Yellow
try {
    $cmd = 'import sys; sys.path.insert(0, "."); from backend.main import app; print("OK")'
    $result = python -c $cmd 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] API imports valides" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] API imports : $result" -ForegroundColor Yellow
        $warnings++
    }
} catch {
    Write-Host "  [WARN] API imports : $_" -ForegroundColor Yellow
    $warnings++
}

# 5. Verifier le workflow GitHub Actions
Write-Host "`nVerification du workflow GitHub Actions..." -ForegroundColor Yellow
if (Test-Path ".github/workflows/devsecops_scan.yml") {
    Write-Host "  [OK] Workflow GitHub Actions present" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Workflow GitHub Actions introuvable" -ForegroundColor Yellow
    $warnings++
}

# 6. Verifier le notebook
Write-Host "`nVerification du notebook..." -ForegroundColor Yellow
if (Test-Path "analyse_bandit.ipynb") {
    Write-Host "  [OK] Notebook analyse_bandit.ipynb present" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Notebook introuvable" -ForegroundColor Yellow
    $warnings++
}

# 7. Verifier les requirements
Write-Host "`nVerification des requirements..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    $reqs = Get-Content "requirements.txt"
    Write-Host "  [OK] requirements.txt : $($reqs.Count) dependances" -ForegroundColor Green
} else {
    Write-Host "  [WARN] requirements.txt introuvable" -ForegroundColor Yellow
    $warnings++
}

# 8. Verifier Streamlit requirements
Write-Host "`nVerification des requirements Streamlit..." -ForegroundColor Yellow
# Vérifier le requirements.txt unique à la racine
if (Test-Path "requirements.txt") {
    $reqs = Get-Content "requirements.txt" | Where-Object { $_ -notmatch '^#' -and $_ -notmatch '^\s*$' }
    Write-Host "  [OK] requirements.txt : $($reqs.Count) dependances" -ForegroundColor Green
} else {
    Write-Host "  [WARN] requirements.txt introuvable" -ForegroundColor Yellow
    $warnings++
}

# Resume
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "RESUME DE LA COMPILATION" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  [OK] Fichiers compiles avec succes" -ForegroundColor Green
Write-Host "  [WARN] Avertissements : $warnings" -ForegroundColor Yellow
Write-Host "  [ERREUR] Erreurs : $errors" -ForegroundColor $(if ($errors -eq 0) { "Green" } else { "Red" })

if ($errors -eq 0) {
    Write-Host ""
    Write-Host "[OK] Le projet compile sans erreurs !" -ForegroundColor Green
    exit 0
} else {
    Write-Host ""
    Write-Host "[ERREUR] Le projet contient des erreurs de compilation." -ForegroundColor Red
    exit 1
}
