<#
.SYNOPSIS
    HunterOs Harness installer for Windows (PowerShell 5.1+).

.DESCRIPTION
    Creates a dedicated virtualenv at ~\.hunteros\venv and installs the
    harness into it:
      1. If this script lives inside a checkout (pyproject.toml next to it),
         installs that checkout editable: pip install -e <checkout>.
      2. Otherwise tries PyPI: pip install hunteros-harness.
      3. Otherwise falls back to pip install git+<RepoUrl>.

    The script is idempotent: re-running it reuses the existing venv and
    refreshes the installation.

.PARAMETER RepoUrl
    Git URL to install from when no local checkout and no PyPI release exist.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install.ps1 -RepoUrl https://github.com/OWNER/HunterOsHarness.git
#>
param(
    [string]$RepoUrl = "https://github.com/OWNER/HunterOsHarness.git"
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Ok([string]$Message) { Write-Host "    $Message" -ForegroundColor Green }
function Write-Fail([string]$Message) {
    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "HunterOs Harness installer" -ForegroundColor Magenta
Write-Host "evidence or nothing" -ForegroundColor DarkGray
Write-Host ""

# --- 1. Locate a Python >= 3.10 --------------------------------------------

$pythonExe = $null
$pythonArgs = @()

function Test-PythonVersion([string]$Exe, [string[]]$ExeArgs) {
    & $Exe @ExeArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    return ($LASTEXITCODE -eq 0)
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    if (Test-PythonVersion "py" @("-3")) {
        $pythonExe = "py"
        $pythonArgs = @("-3")
    }
}
if (-not $pythonExe -and (Get-Command python -ErrorAction SilentlyContinue)) {
    if (Test-PythonVersion "python" @()) {
        $pythonExe = "python"
        $pythonArgs = @()
    }
}
if (-not $pythonExe) {
    Write-Fail "Python 3.10+ not found. Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then re-run this script."
}

$pythonLabel = (& $pythonExe @pythonArgs --version 2>&1 | Out-String).Trim()
Write-Step "Found Python: $pythonLabel"

# --- 2. Create or reuse the venv --------------------------------------------

$venvDir = Join-Path $HOME ".hunteros\venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"

if (Test-Path $venvPython) {
    Write-Step "Reusing existing venv: $venvDir"
} else {
    Write-Step "Creating venv at $venvDir"
    & $pythonExe @pythonArgs -m venv "$venvDir"
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $venvPython)) {
        Write-Fail "Failed to create the venv. Delete $venvDir and re-run."
    }
}

Write-Step "Upgrading pip (quiet)"
& $venvPython -m pip install --upgrade pip --quiet --disable-pip-version-check
if ($LASTEXITCODE -ne 0) { Write-Fail "pip upgrade failed — check your network/proxy settings." }

# --- 3. Install the harness ---------------------------------------------------

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$localCheckout = Test-Path (Join-Path $scriptDir "pyproject.toml")

if ($localCheckout) {
    Write-Step "Local checkout detected — installing editable from $scriptDir"
    & $venvPython -m pip install -e "$scriptDir" --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) { Write-Fail "Editable install failed — see the pip output above." }
} else {
    Write-Step "Installing hunteros-harness from PyPI"
    & $venvPython -m pip install hunteros-harness --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) {
        Write-Step "PyPI install failed — falling back to git ($RepoUrl)"
        & $venvPython -m pip install "git+$RepoUrl" --disable-pip-version-check
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "All install sources failed. Check the RepoUrl and your network, then re-run."
        }
    }
}

& $venvPython -c "import hunter; print('hunteros-harness', hunter.__version__, 'installed')" | Write-Host
if ($LASTEXITCODE -ne 0) { Write-Fail "Installation verification failed: the 'hunter' package did not import cleanly." }

# --- 4. Next steps --------------------------------------------------------------

Write-Host ""
Write-Host "Installed. Next steps:" -ForegroundColor Magenta
Write-Host ""
Write-Host "  1. Activate the venv (or use the full path):" -ForegroundColor White
Write-Host "       $venvDir\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "  2. Check the environment:" -ForegroundColor White
Write-Host "       hunter doctor" -ForegroundColor Yellow
Write-Host "  3. Configure a brain (LLM provider wizard, optional):" -ForegroundColor White
Write-Host "       hunter init" -ForegroundColor Yellow
Write-Host "  4. Run the one-command demo (local practice target, deterministic scan):" -ForegroundColor White
Write-Host "       hunter demo" -ForegroundColor Yellow
Write-Host "  5. Open the dashboard:" -ForegroundColor White
Write-Host "       hunter tui" -ForegroundColor Yellow
Write-Host ""
Write-Host "Scan only systems you own or are explicitly authorized to test." -ForegroundColor DarkGray
