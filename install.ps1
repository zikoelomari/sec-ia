$ErrorActionPreference = "Stop"

# Paramètres avec gestion manuelle pour compatibilité
$Python = ""
$VenvDir = ".venv"

# Parser les arguments si fournis
if ($args.Count -gt 0) {
    $Python = $args[0]
}
if ($args.Count -gt 1) {
    $VenvDir = $args[1]
}

# Resolve Python interpreter (prefer 3.13, allow override via $env:PYTHON_EXE or -Python)
$targetVersion = "3.13"
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = $env:PYTHON_EXE
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    try { 
        $result = & py -$targetVersion -c "import sys; print(sys.executable)" 2>&1
        if ($LASTEXITCODE -eq 0 -and $result) { 
            $Python = $result.ToString().Trim()
        }
    } catch { 
        $Python = $null
    }
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    try { 
        $result = & py -3 -c "import sys; print(sys.executable)" 2>&1
        if ($LASTEXITCODE -eq 0 -and $result) { 
            $Python = $result.ToString().Trim()
        }
    } catch { 
        $Python = $null
    }
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python = "python"
}

Write-Host "Using interpreter (target $targetVersion+): $Python" -ForegroundColor Cyan
try {
    $pyVersion = & $Python -c "import sys; print('.'.join(map(str, sys.version_info[:3])))"
    if ($pyVersion -notlike "3.13.*") {
        Write-Warning "Detected Python $pyVersion; project targets 3.13.9. Install Python 3.13.x for best compatibility."
    }
} catch {
    Write-Warning "Could not detect Python version. Continuing anyway..."
}

if (-not (Test-Path $VenvDir)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    & $Python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment. Exiting."
        exit 1
    }
} else {
    Write-Host "Virtual environment already exists at $VenvDir" -ForegroundColor Green
}

$activate = Join-Path $VenvDir "Scripts\Activate.ps1"
if (-not (Test-Path $activate)) {
    Write-Error "Virtual environment activation script not found at $activate"
    exit 1
}

Write-Host "Activating virtual environment..." -ForegroundColor Yellow
. $activate

Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Warning "pip upgrade failed, but continuing..."
}

Write-Host "Installing dependencies from requirements.txt..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install dependencies from requirements.txt"
        exit 1
    }
} else {
    Write-Error "requirements.txt not found in current directory"
    exit 1
}

Write-Host "Installing optional tools (semgrep, reportlab)..." -ForegroundColor Yellow
try {
    pip install semgrep reportlab
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] semgrep and reportlab installed" -ForegroundColor Green
    } else {
        Write-Warning "Failed to install semgrep/reportlab via pip. You may need build tools or to pin versions compatible with your Python runtime."
    }
} catch {
    Write-Warning "Failed to install semgrep/reportlab via pip. You may need build tools or to pin versions compatible with your Python runtime."
}

if (Get-Command snyk -ErrorAction SilentlyContinue) {
    Write-Host "[OK] Snyk CLI detected on PATH. Run 'snyk auth' before launching scans." -ForegroundColor Green
} else {
    Write-Warning "Snyk CLI not installed. Install via 'npm install -g snyk' or download the binary, then run 'snyk auth'."
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  INSTALLATION TERMINEE [OK]            " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Environment ready. Activate with:" -ForegroundColor Cyan
Write-Host "  & $activate" -ForegroundColor White
Write-Host ""
