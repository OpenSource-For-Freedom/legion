#Requires -Version 5.1
<#
.SYNOPSIS
    Legion SIEM – Windows install script
.DESCRIPTION
    Downloads and installs the Legion CLI, TUI, and web dashboard to %LOCALAPPDATA%\legion\bin.
.EXAMPLE
    irm https://raw.githubusercontent.com/tbgor/legion/main/scripts/install.ps1 | iex
#>

[CmdletBinding()]
param(
    [string]$BinDir  = "$env:LOCALAPPDATA\legion\bin",
    [string]$DataDir = "$env:APPDATA\legion"
)

$ErrorActionPreference = 'Stop'
$REPO = 'tbgor/legion'
$TARGET = 'x86_64-pc-windows-msvc'

Write-Host "Legion SIEM – Windows Installer" -ForegroundColor Cyan
Write-Host "─────────────────────────────────"

# ── Detect latest release ───────────────────────────────────────────────────
Write-Host "Fetching latest release info..."
try {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$REPO/releases/latest" -Headers @{
        'Accept' = 'application/vnd.github.v3+json'
        'User-Agent' = 'legion-installer'
    }
    $tag = $release.tag_name
} catch {
    Write-Error "Could not fetch release info: $_"
    exit 1
}

Write-Host "Installing Legion $tag for $TARGET..."

# ── Download ─────────────────────────────────────────────────────────────────
$archive    = "legion-$tag-$TARGET.tar.gz"
$url        = "https://github.com/$REPO/releases/download/$tag/$archive"
$tmp        = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "legion_install_$(Get-Random)")

try {
    Write-Host "Downloading $archive ..."
    Invoke-WebRequest -Uri $url -OutFile "$tmp\$archive" -UseBasicParsing

    # Extract (tar available on Windows 10+ build 17063)
    Push-Location $tmp
    tar -xzf $archive
    $extracted = "$tmp\legion-$tag-$TARGET"
    Pop-Location

    # ── Install binaries ────────────────────────────────────────────────────
    New-Item -ItemType Directory -Path $BinDir  -Force | Out-Null
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

    Copy-Item "$extracted\legion.exe"     "$BinDir\legion.exe"     -Force
    Copy-Item "$extracted\legion-tui.exe" "$BinDir\legion-tui.exe" -Force
    Copy-Item "$extracted\legion-web.exe" "$BinDir\legion-web.exe" -Force

    Write-Host ""
    Write-Host "Installed!" -ForegroundColor Green
    Write-Host "  CLI:      $BinDir\legion.exe"
    Write-Host "  TUI:      $BinDir\legion-tui.exe"
    Write-Host "  Web:      $BinDir\legion-web.exe"
    Write-Host "  Data dir: $DataDir"
    Write-Host ""

    # ── PATH ────────────────────────────────────────────────────────────────
    $userPath = [Environment]::GetEnvironmentVariable('PATH', 'User')
    if ($userPath -notlike "*$BinDir*") {
        [Environment]::SetEnvironmentVariable('PATH', "$userPath;$BinDir", 'User')
        Write-Host "Added $BinDir to user PATH (restart terminal to apply)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor Cyan
    Write-Host "  legion feeds refresh   # pull latest threat feeds"
    Write-Host "  legion scan .          # scan current directory"
    Write-Host "  legion alerts          # view active alerts"
    Write-Host "  legion-tui             # launch terminal dashboard"
    Write-Host "  legion-web             # launch browser dashboard (http://localhost:3000)"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
