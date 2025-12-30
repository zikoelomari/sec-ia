# Script pour démarrer tous les services (Backend + Frontend HTML + Streamlit)
Write-Host "=== DEMARRAGE DE TOUS LES SERVICES ===" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

# Vérifier que l'environnement virtuel existe
if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "[ERREUR] Environnement virtuel introuvable. Executez d'abord install.ps1" -ForegroundColor Red
    exit 1
}

Write-Host "`nDemarrage des services..." -ForegroundColor Yellow

# Terminal 1: Backend API
Write-Host "`n[1/2] Demarrage Backend API..." -ForegroundColor Yellow
$backendScript = @"
cd '$projectRoot'
& '.\.venv\Scripts\Activate.ps1'
`$env:SAVE_REPORTS = '1'
`$env:REPORTS_DIR = 'analyses'
Write-Host 'Backend API demarre sur http://localhost:8000' -ForegroundColor Green
Write-Host 'API accessible sur: http://localhost:8000/api' -ForegroundColor Cyan
Write-Host 'Documentation API: http://localhost:8000/docs' -ForegroundColor Cyan
Write-Host '[ACTIF] Sauvegarde automatique des rapports dans analyses/' -ForegroundColor Green
python -m uvicorn backend.main:app --reload --port 8000
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendScript

# Attendre un peu avant de démarrer Streamlit
Start-Sleep -Seconds 2

# Terminal 2: Streamlit (Interface Unifiee)
Write-Host "[2/2] Demarrage Streamlit (Interface Unifiee)..." -ForegroundColor Yellow
$streamlitScript = @"
cd '$projectRoot'
& '.\.venv\Scripts\Activate.ps1'
cd frontend_streamlit
Write-Host 'Streamlit Interface Unifiee demarre sur http://localhost:8502' -ForegroundColor Green
Write-Host 'Interface complete: Code + GitHub + Dashboard + Historique' -ForegroundColor Cyan
streamlit run app_unified.py --server.port 8502
"@

Start-Process powershell -ArgumentList "-NoExit", "-Command", $streamlitScript

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "SERVICES DEMARRES" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  - Backend API: http://localhost:8000" -ForegroundColor White
Write-Host "  - API Documentation: http://localhost:8000/docs" -ForegroundColor White
Write-Host "  - Streamlit Unifie: http://localhost:8502" -ForegroundColor White
Write-Host "    (Code + GitHub + Dashboard + Historique)" -ForegroundColor Cyan
Write-Host "`nAppuyez sur une touche pour continuer..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

