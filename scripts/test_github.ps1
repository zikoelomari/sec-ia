# Script de test pour l'analyse de dépôts GitHub
Write-Host "=== TEST ANALYSE GITHUB ===" -ForegroundColor Cyan

$projectRoot = $PSScriptRoot + "\.."
Set-Location $projectRoot

# Vérifier que l'API est démarrée
try {
    $testResponse = Invoke-WebRequest -Uri "http://localhost:8000/api" -Method GET -TimeoutSec 2 -ErrorAction Stop
    Write-Host "[OK] API accessible sur http://localhost:8000" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] L'API n'est pas accessible sur http://localhost:8000" -ForegroundColor Red
    Write-Host "       Demarrez d'abord l'API avec: python -m uvicorn backend.main:app --reload --port 8000" -ForegroundColor Yellow
    exit 1
}

# Demander l'URL du dépôt
Write-Host "`nEntrez l'URL du depot GitHub a analyser:" -ForegroundColor Yellow
Write-Host "  Exemples:" -ForegroundColor White
Write-Host "    - https://github.com/psf/requests" -ForegroundColor Cyan
Write-Host "    - https://github.com/python/cpython" -ForegroundColor Cyan
Write-Host "    - https://github.com/OWNER/REPO/tree/branch-name" -ForegroundColor Cyan
Write-Host ""
$repoUrl = Read-Host "URL du depot"

if ([string]::IsNullOrWhiteSpace($repoUrl)) {
    Write-Host "[ERREUR] URL vide" -ForegroundColor Red
    exit 1
}

# Validation de l'URL
if (-not $repoUrl.Contains("github.com")) {
    Write-Host "[ERREUR] URL GitHub invalide" -ForegroundColor Red
    exit 1
}

# Préparer la requête
$body = @{
    url = $repoUrl.Trim()
    scanners = @("bandit", "semgrep", "gemini_detector")
} | ConvertTo-Json

Write-Host "`nTest de l'analyse GitHub..." -ForegroundColor Yellow
Write-Host "  URL: $repoUrl" -ForegroundColor White
Write-Host "  Scanners: bandit, semgrep, gemini_detector" -ForegroundColor White
Write-Host "  En cours..." -ForegroundColor Yellow

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/analyze-github" `
        -Method POST `
        -Body $body `
        -ContentType "application/json" `
        -TimeoutSec 300  # 5 minutes timeout
    
    Write-Host "`n[OK] Analyse reussie!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "RESULTATS" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Depot: $($response.repo)" -ForegroundColor White
    Write-Host "  Langage: $($response.language)" -ForegroundColor White
    Write-Host "  Scanners executes: $($response.scanners.Keys -join ', ')" -ForegroundColor White
    
    # Afficher un résumé des findings
    $totalFindings = 0
    foreach ($scannerName in $response.scanners.Keys) {
        if ($scannerName -ne "_meta") {
            $scannerData = $response.scanners[$scannerName]
            if ($scannerData.issues) {
                $count = $scannerData.issues.Count
                $totalFindings += $count
                Write-Host "  $scannerName : $count findings" -ForegroundColor $(if ($count -gt 0) { "Yellow" } else { "Green" })
            }
        }
    }
    
    Write-Host "  Total findings: $totalFindings" -ForegroundColor $(if ($totalFindings -gt 0) { "Yellow" } else { "Green" })
    
    # Sauvegarder le résultat
    $outputFile = "test_github_result_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $response | ConvertTo-Json -Depth 10 | Out-File $outputFile -Encoding utf8
    Write-Host "`nResultat sauvegarde dans: $outputFile" -ForegroundColor Cyan
    
} catch {
    Write-Host "`n[ERREUR] $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor Yellow
    }
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Reponse serveur: $responseBody" -ForegroundColor Yellow
    }
    exit 1
}

Write-Host "`n=== TEST TERMINE ===" -ForegroundColor Green

