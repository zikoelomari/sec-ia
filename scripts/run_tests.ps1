# Script pour exécuter tous les tests
Write-Host "=== EXECUTION DES TESTS ===" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

# Activer l'environnement virtuel
if (Test-Path ".venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
} else {
    Write-Host "[ERREUR] Environnement virtuel introuvable" -ForegroundColor Red
    Write-Host "Executez d'abord install.ps1 pour creer l'environnement virtuel" -ForegroundColor Yellow
    exit 1
}

Write-Host "`nExécution des tests unitaires..." -ForegroundColor Yellow
pytest backend/tests/ -v --tb=short

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n[ATTENTION] Certains tests ont echoue" -ForegroundColor Yellow
} else {
    Write-Host "`n[OK] Tous les tests sont passes" -ForegroundColor Green
}

Write-Host "`nGénération du rapport de couverture..." -ForegroundColor Yellow
pytest backend/tests/ --cov=backend --cov-report=html --cov-report=term

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "Rapport de couverture genere dans: htmlcov/index.html" -ForegroundColor Green
Write-Host "Ouvrez htmlcov/index.html dans votre navigateur pour voir le rapport detaille" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

