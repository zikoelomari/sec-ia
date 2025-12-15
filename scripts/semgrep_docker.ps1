# semgrep_docker.ps1
# Lance Semgrep via Docker pour éviter les problèmes d'encodage sur Windows

param(
    [Parameter(Mandatory=$false)]
    [string]$Path = ".",
    
    [Parameter(Mandatory=$false)]
    [string]$Config = "auto",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "semgrep_results.json"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Semgrep via Docker (Windows-safe)    " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier que Docker est installé
try {
    $dockerVersion = docker --version
    Write-Host "[OK] Docker détecté: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Docker n'est pas installé ou n'est pas dans le PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "Installation Docker Desktop:" -ForegroundColor Yellow
    Write-Host "  https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Résoudre le chemin absolu
$AbsolutePath = Resolve-Path $Path

Write-Host "[INFO] Chemin à scanner: $AbsolutePath" -ForegroundColor Cyan
Write-Host "[INFO] Configuration Semgrep: $Config" -ForegroundColor Cyan
Write-Host "[INFO] Fichier de sortie: $OutputFile" -ForegroundColor Cyan
Write-Host ""

# Construire la commande Docker
# Note: Sur Windows, on monte le répertoire en lecture seule pour la sécurité
$dockerCommand = @(
    "run",
    "--rm",
    "-v", "${AbsolutePath}:/src:ro",
    "returntocorp/semgrep",
    "semgrep",
    "--config", $Config,
    "--json",
    "/src"
)

Write-Host "[EXEC] docker $($dockerCommand -join ' ')" -ForegroundColor Yellow
Write-Host ""

# Exécuter Semgrep via Docker
try {
    $output = docker @dockerCommand 2>&1
    
    # Sauvegarder la sortie JSON
    $output | Out-File -FilePath $OutputFile -Encoding UTF8
    
    Write-Host "[OK] Scan Semgrep terminé" -ForegroundColor Green
    Write-Host "[OK] Résultats sauvegardés dans: $OutputFile" -ForegroundColor Green
    
    # Parser le JSON pour afficher un résumé
    try {
        $results = $output | ConvertFrom-Json
        $findings = $results.results.Count
        Write-Host ""
        Write-Host "[INFO] Résumé:" -ForegroundColor Cyan
        Write-Host "  - $findings issue(s) détectée(s)" -ForegroundColor White
        
        # Compter par sévérité
        $errors = ($results.results | Where-Object { $_.extra.severity -eq "ERROR" }).Count
        $warnings = ($results.results | Where-Object { $_.extra.severity -eq "WARNING" }).Count
        $info = ($results.results | Where-Object { $_.extra.severity -eq "INFO" }).Count
        
        if ($errors -gt 0) {
            Write-Host "  - ERROR: $errors" -ForegroundColor Red
        }
        if ($warnings -gt 0) {
            Write-Host "  - WARNING: $warnings" -ForegroundColor Yellow
        }
        if ($info -gt 0) {
            Write-Host "  - INFO: $info" -ForegroundColor Cyan
        }
    } catch {
        Write-Host "[WARN] Impossible de parser les résultats JSON" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "[ERREUR] Erreur lors de l'exécution de Semgrep : $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Scan terminé avec succès [OK]         " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

