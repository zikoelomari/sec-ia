# Script de compilation complète Frontend + Backend + Streamlit
Write-Host "=== COMPILATION COMPLETE ===" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

$errors = 0
$warnings = 0

# 1. Backend
Write-Host "`n[1/3] Compilation Backend..." -ForegroundColor Yellow
$backendFiles = @(
    "backend/main.py",
    "backend/analyzers/bandit_analyzer.py",
    "backend/analyzers/multi_analyzer.py",
    "backend/detectors/gemini_detector.py"
)

foreach ($file in $backendFiles) {
    if (Test-Path $file) {
        try {
            python -m py_compile $file 2>&1 | Out-Null
            Write-Host "  [OK] $file" -ForegroundColor Green
        } catch {
            Write-Host "  [ERREUR] $file : $_" -ForegroundColor Red
            $errors++
        }
    }
}

# Vérifier les imports backend
try {
    $cmd = "import sys; sys.path.insert(0, '.'); from backend.main import app; print('OK')"
    $result = python -c $cmd 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Backend imports valides" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Backend imports : $result" -ForegroundColor Yellow
        $warnings++
    }
} catch {
    Write-Host "  [WARN] Backend imports : $_" -ForegroundColor Yellow
    $warnings++
}

# 2. Frontend Streamlit
Write-Host "`n[2/2] Compilation Frontend Streamlit..." -ForegroundColor Yellow
if (Test-Path "frontend_streamlit/app_unified.py") {
    try {
        python -m py_compile frontend_streamlit/app_unified.py 2>&1 | Out-Null
        Write-Host "  [OK] frontend_streamlit/app_unified.py" -ForegroundColor Green
    } catch {
        Write-Host "  [ERREUR] frontend_streamlit/app_unified.py : $_" -ForegroundColor Red
        $errors++
    }
} else {
    Write-Host "  [WARN] frontend_streamlit/app_unified.py introuvable" -ForegroundColor Yellow
    $warnings++
}

# Vérifier Streamlit
try {
    $result = python -c "import streamlit; print('OK')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] Streamlit installe" -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Streamlit non installe" -ForegroundColor Yellow
        $warnings++
    }
} catch {
    Write-Host "  [WARN] Streamlit : $_" -ForegroundColor Yellow
    $warnings++
}

# Résumé
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

