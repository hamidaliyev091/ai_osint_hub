#Requires -Version 5.1
<#
.SYNOPSIS
One-click bootstrap and launcher for AI OSINT Hub (Windows PowerShell 5.1).
#>

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$VenvDir = Join-Path $RepoRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

function Find-SystemPython {
    $candidates = @("python", "py")
    foreach ($cmd in $candidates) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if (-not $found) { continue }
        try {
            if ($cmd -eq "py") {
                $ver = & $found.Source -3 -c "import sys; print('{}.{}'.format(sys.version_info[0], sys.version_info[1]))" 2>$null
                if ($LASTEXITCODE -eq 0 -and $ver) {
                    $parts = $ver.Trim().Split(".")
                    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10)) {
                        return @($found.Source, "-3")
                    }
                }
            } else {
                $ver = & $found.Source -c "import sys; print('{}.{}'.format(sys.version_info[0], sys.version_info[1]))" 2>$null
                if ($LASTEXITCODE -eq 0 -and $ver) {
                    $parts = $ver.Trim().Split(".")
                    if ([int]$parts[0] -gt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 10)) {
                        return @($found.Source)
                    }
                }
            }
        } catch {
            continue
        }
    }
    return $null
}

$UvCmd = Get-Command "uv" -ErrorAction SilentlyContinue

if (-not (Test-Path $VenvPython)) {
    Write-Host "[ai-osint-hub] Creating virtual environment at $VenvDir ..."
    if ($UvCmd) {
        & $UvCmd.Source venv $VenvDir
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Failed to create .venv with uv. Verify uv is working or install Python 3.10+ from https://www.python.org/downloads/."
            exit 1
        }
    } else {
        $SysPy = Find-SystemPython
        if (-not $SysPy) {
            Write-Host ""
            Write-Host "ERROR: Neither 'uv' nor Python 3.10+ was found on PATH." -ForegroundColor Red
            Write-Host "Install uv:     powershell -ExecutionPolicy ByPass -c `"irm https://astral.sh/uv/install.ps1 | iex`""
            Write-Host "Or install Python 3.11+: https://www.python.org/downloads/"
            exit 1
        }
        if ($SysPy.Count -gt 1) {
            & $SysPy[0] $SysPy[1] -m venv $VenvDir
        } else {
            & $SysPy[0] -m venv $VenvDir
        }
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPython)) {
            Write-Host "ERROR: Failed to create virtual environment at $VenvDir." -ForegroundColor Red
            exit 1
        }
    }
}

& $VenvPython -c "import hub" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[ai-osint-hub] Installing package into .venv ..."
    if ($UvCmd) {
        & $UvCmd.Source pip install --python $VenvPython -e $RepoRoot
    } else {
        & $VenvPython -m pip install --upgrade pip
        & $VenvPython -m pip install -e $RepoRoot
    }
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install ai-osint-hub into $VenvDir." -ForegroundColor Red
        exit 1
    }
}

Write-Host "[ai-osint-hub] Launching Web Workbench ..."
& $VenvPython -m hub.cli web --open @args
exit $LASTEXITCODE
