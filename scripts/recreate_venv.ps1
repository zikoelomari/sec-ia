# Recreate .venv safely using Python 3.13 (target 3.13.9)
# Usage: open PowerShell in repo root and run: .\scripts\recreate_venv.ps1

Write-Host "Recreating .venv in: $PWD" -ForegroundColor Cyan

# Target interpreter discovery (prefer 3.13; allow override via $env:PYTHON_EXE)
$targetVersion = "3.13"
$pyTarget = $env:PYTHON_EXE
if (-not $pyTarget) {
    try { $pyTarget = (& py -$targetVersion -c "import sys; print(sys.executable)") 2>$null } catch { }
}

# Fallback to latest available via py launcher
if (-not $pyTarget) {
    Write-Host "py -$targetVersion not found. Trying py -3..." -ForegroundColor Yellow
    try { $pyTarget = (& py -3 -c "import sys; print(sys.executable)") 2>$null } catch { }
}

# Allow manual override via first positional argument (full python.exe path)
if (-not $pyTarget -and $args.Count -ge 1) {
    $pyTarget = $args[0]
}

if (-not $pyTarget) {
    Write-Host "No suitable python interpreter found. You can pass a full python.exe path as an argument." -ForegroundColor Red
    Write-Host "Example: & 'C:\\Users\\You\\AppData\\Local\\Programs\\Python\\Python313\\python.exe' -m venv .venv" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using interpreter (target $targetVersion+): $pyTarget" -ForegroundColor Green

# Deactivate if a virtualenv is active
if ($env:VIRTUAL_ENV) {
    Write-Host "Deactivating active virtualenv..." -ForegroundColor Cyan
    try { deactivate } catch { }
}

# Remove existing .venv
if (Test-Path -LiteralPath .\.venv) {
    Write-Host "Removing existing .venv (this may take a few seconds)..." -ForegroundColor Cyan
    Remove-Item -LiteralPath .\.venv -Recurse -Force -ErrorAction SilentlyContinue
}

# Create new venv using the selected interpreter
Write-Host "Creating new virtualenv..." -ForegroundColor Cyan
& $pyTarget -m venv .venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to create venv with $pyTarget" -ForegroundColor Red
    exit 2
}

# Activate and install dependencies
Write-Host "Activating new .venv and installing dependencies..." -ForegroundColor Cyan
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
. .\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
# Recommended optional tools (attempt, but continue on failure)
try {
    & pip install semgrep bandit "uvicorn[standard]"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Optional installs failed; continue if not needed." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Optional installs failed; continue if not needed." -ForegroundColor Yellow
}

Write-Host "Virtualenv recreated and dependencies installed." -ForegroundColor Green
Write-Host "Activate it with: . \.venv\Scripts\Activate.ps1" -ForegroundColor Cyan
