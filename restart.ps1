# restart.ps1 — stop the running (possibly elevated) legion-web, rebuild, relaunch.
# If not already running as admin, re-launches this script elevated via UAC.

param(
    [string]$ScanRoot = "F:\dev"
)

# ── Self-elevate if needed ────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting administrator rights to stop the running legion-web..." -ForegroundColor Cyan
    $scriptPath = $MyInvocation.MyCommand.Path
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -ScanRoot `"$ScanRoot`"" -Wait
    exit $LASTEXITCODE
}

Set-Location $PSScriptRoot

# ── Stop running instance ─────────────────────────────────────────────────────
Write-Host "Stopping legion-web..." -ForegroundColor Yellow
Stop-Process -Name legion-web -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 800

# ── Build ─────────────────────────────────────────────────────────────────────
Write-Host "Building legion-web..." -ForegroundColor Cyan
cargo build -p legion-web
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed." -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

# ── Launch ────────────────────────────────────────────────────────────────────
# Launch DETACHED (Start-Process) so the server survives this (elevated) window
# closing. A foreground `&` launch dies with the window, orphaning the browser
# page with "Failed to fetch". Re-run `make legion` to rebuild + restart it.
Write-Host "Launching legion-web (background) at http://localhost:3000 ..." -ForegroundColor Green
$exe = Join-Path $PSScriptRoot "target\debug\legion-web.exe"
Start-Process -FilePath $exe -ArgumentList "--scan-root", $ScanRoot, "--no-elevate" -WorkingDirectory $PSScriptRoot
Start-Sleep -Seconds 2
if (Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue) {
    Write-Host "legion-web is running at http://localhost:3000 (background). Close it with: make stop" -ForegroundColor Cyan
} else {
    Write-Host "Warning: legion-web did not bind port 3000 - check for errors above." -ForegroundColor Yellow
}
