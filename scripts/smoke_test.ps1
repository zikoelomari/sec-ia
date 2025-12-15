# smoke_test.ps1
# Test rapide de l'API pour vérifier que tout fonctionne

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SMOKE TEST - API Security Analysis   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$API_URL = "http://localhost:8000"
$API_KEY = $env:API_KEY

# Construire les headers
$headers = @{
    "Content-Type" = "application/json"
}

if ($API_KEY) {
    $headers["X-API-KEY"] = $API_KEY
    Write-Host "[INFO] API Key configurée" -ForegroundColor Green
} else {
    Write-Host "[WARN] Aucune API Key - Certains tests peuvent échouer" -ForegroundColor Yellow
}

Write-Host ""

# Test 1: Vérifier que l'API est accessible
Write-Host "[TEST 1] Vérification de l'API..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "$API_URL/" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[OK] API accessible (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] API non accessible : $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 2: Vérifier les providers disponibles
Write-Host "[TEST 2] Vérification des providers IA..." -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "$API_URL/api/providers" -Method GET -Headers $headers -TimeoutSec 5
    $providers = $response.available_providers -join ", "
    Write-Host "[OK] Providers disponibles: $providers" -ForegroundColor Green
    
    if ($response.openai_configured) {
        Write-Host "  -> OpenAI configuré" -ForegroundColor Green
    } else {
        Write-Host "  -> OpenAI non configuré" -ForegroundColor Yellow
    }
    
    if ($response.anthropic_configured) {
        Write-Host "  -> Anthropic configuré" -ForegroundColor Green
    } else {
        Write-Host "  -> Anthropic non configuré" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERREUR] Erreur lors de la vérification des providers : $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 3: Analyse rapide d'un snippet Python
Write-Host "[TEST 3] Analyse d'un snippet Python simple..." -ForegroundColor Cyan
$body = @{
    language = "python"
    code = "password = 'hardcoded123'"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$API_URL/analyze-fast" -Method POST -Headers $headers -Body $body -TimeoutSec 10
    $high = $response.scanners.bandit.issues | Where-Object { $_.severity -eq "HIGH" } | Measure-Object | Select-Object -ExpandProperty Count
    Write-Host "[OK] Analyse terminée - $high vulnérabilités HIGH détectées" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Erreur lors de l'analyse : $_" -ForegroundColor Red
    exit 1
}

Write-Host ""

# Test 4: Génération avec simulation (toujours disponible)
Write-Host "[TEST 4] Test de génération avec simulation..." -ForegroundColor Cyan
$body = @{
    description = "user login function"
    language = "python"
    provider = "simulate"
    scanners = @("bandit", "gemini_detector")
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$API_URL/generate-and-analyze" -Method POST -Headers $headers -Body $body -TimeoutSec 15
    $code_length = $response.generation.code.Length
    $tokens = $response.generation.tokens_used
    Write-Host "[OK] Génération réussie - $code_length caractères, $tokens tokens" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Erreur lors de la génération : $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  TOUS LES TESTS SONT PASSÉS [OK]        " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "L'API est fonctionnelle et prête à l'emploi!" -ForegroundColor Green

