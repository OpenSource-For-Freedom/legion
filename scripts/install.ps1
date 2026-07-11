#Requires -Version 5.1
<#
.SYNOPSIS
    Legion SIEM – Windows install script
.DESCRIPTION
    Downloads and installs the Legion app (the web dashboard) to %LOCALAPPDATA%\legion\bin.
.EXAMPLE
    irm https://raw.githubusercontent.com/OpenSource-For-Freedom/legion/main/scripts/install.ps1 | iex
#>

[CmdletBinding()]
param(
    [string]$BinDir  = "$env:LOCALAPPDATA\legion\bin",
    [string]$DataDir = "$env:APPDATA\legion",
    [switch]$SkipAdminRelaunch,
    [switch]$SkipOllamaInstall,
    [switch]$InstallOllama
)

$ErrorActionPreference = 'Stop'
$REPO = 'OpenSource-For-Freedom/legion'
$TARGET = 'x86_64-pc-windows-msvc'

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Elevation {
    if ($SkipAdminRelaunch) {
        return
    }
    if (Test-IsAdmin) {
        return
    }

    Write-Host "Requesting Administrator elevation (UAC)..." -ForegroundColor Yellow

    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        "`"$PSCommandPath`""
        '-SkipAdminRelaunch'
        '-BinDir'
        "`"$BinDir`""
        '-DataDir'
        "`"$DataDir`""
    )

    if ($SkipOllamaInstall) {
        $argList += '-SkipOllamaInstall'
    }
    if ($InstallOllama) {
        $argList += '-InstallOllama'
    }

    $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList -PassThru
    $proc.WaitForExit()
    exit $proc.ExitCode
}

function Add-PathEntry {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [ValidateSet('User', 'Machine')][string]$Scope = 'User'
    )

    if (-not (Test-Path $Value)) {
        return
    }

    $current = [Environment]::GetEnvironmentVariable('PATH', $Scope)
    $parts = @()
    if ($current) {
        $parts = $current -split ';' | Where-Object { $_ -and $_.Trim() }
    }

    if ($parts -contains $Value) {
        return
    }

    $newPath = if ($current) { "$current;$Value" } else { $Value }
    [Environment]::SetEnvironmentVariable('PATH', $newPath, $Scope)
    Write-Host "Added $Value to $Scope PATH" -ForegroundColor Yellow
}

function Install-Ollama {
    # L8 (audit 2026-07): installing Ollama (legacy runtime) is opt-in. The
    # default runtime is the OpenAI-compatible local server, so we do not fetch
    # and silently run a remote installer unless asked.
    if ($SkipOllamaInstall -or -not $InstallOllama) {
        Write-Host "Skipping Ollama install (legacy runtime; pass -InstallOllama to install)." -ForegroundColor Yellow
        return
    }

    if (Get-Command ollama -ErrorAction SilentlyContinue) {
        Write-Host "Ollama already installed." -ForegroundColor Green
        return
    }

    Write-Host "Installing Ollama..." -ForegroundColor Cyan

    $installed = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            winget install -e --id Ollama.Ollama --accept-source-agreements --accept-package-agreements
            $installed = $true
        } catch {
            Write-Host "winget install failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    if (-not $installed) {
        $setupExe = Join-Path $env:TEMP 'OllamaSetup.exe'
        try {
            Invoke-WebRequest -Uri 'https://ollama.com/download/OllamaSetup.exe' -OutFile $setupExe -UseBasicParsing
            $p = Start-Process -FilePath $setupExe -ArgumentList '/S' -PassThru -Wait
            if ($p.ExitCode -ne 0) {
                throw "Installer exited with code $($p.ExitCode)"
            }
            $installed = $true
        } catch {
            Write-Warning "Automatic Ollama install failed. Install manually from https://ollama.com/download"
        } finally {
            Remove-Item $setupExe -Force -ErrorAction SilentlyContinue
        }
    }

    Add-PathEntry -Value 'C:\Program Files\Ollama' -Scope 'Machine'
    if (Test-Path 'C:\Program Files\Ollama') {
        $env:Path = "$env:Path;C:\Program Files\Ollama"
    }

    if (Get-Command ollama -ErrorAction SilentlyContinue) {
        Write-Host "Ollama installed successfully." -ForegroundColor Green
    } else {
        Write-Warning "Ollama was installed but is not available in this session yet. Open a new terminal after install completes."
    }
}

Ensure-Elevation

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

    # ── Integrity check ─────────────────────────────────────────────────────
    # Verify the published SHA-256 before extracting. Override with
    # $env:LEGION_SKIP_CHECKSUM = '1' (not recommended).
    if ($env:LEGION_SKIP_CHECKSUM -ne '1') {
        try {
            Invoke-WebRequest -Uri "$url.sha256" -OutFile "$tmp\$archive.sha256" -UseBasicParsing
        } catch {
            Write-Error "No published checksum for $archive. Set `$env:LEGION_SKIP_CHECKSUM='1' to install anyway."
            exit 1
        }
        $expected = (((Get-Content "$tmp\$archive.sha256" -Raw) -split '\s+') | Where-Object { $_ })[0].ToLower()
        $actual   = (Get-FileHash "$tmp\$archive" -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) {
            Write-Error "Checksum verification FAILED for $archive (expected $expected, got $actual). Aborting."
            exit 1
        }
        Write-Host "Checksum verified." -ForegroundColor Green
    }

    # Extract (tar available on Windows 10+ build 17063)
    Push-Location $tmp
    tar -xzf $archive
    $extracted = "$tmp\legion-$tag-$TARGET"
    Pop-Location

    # ── Install binaries ────────────────────────────────────────────────────
    New-Item -ItemType Directory -Path $BinDir  -Force | Out-Null
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

    Copy-Item "$extracted\legion-web.exe" "$BinDir\legion-web.exe" -Force

    # One-prompt mode: after installer elevation, suppress runtime re-prompts.
    $modeDir = Join-Path $env:ProgramData 'Legion'
    New-Item -ItemType Directory -Path $modeDir -Force | Out-Null
    Set-Content -Path (Join-Path $modeDir 'one_prompt_mode') -Value ("installed=" + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -Encoding Ascii

    Write-Host ""
    Write-Host "Installed!" -ForegroundColor Green
    Write-Host "  App:      $BinDir\legion-web.exe"
    Write-Host "  Data dir: $DataDir"
    Write-Host "  Mode:     one admin prompt at install (runtime elevation prompts disabled)"
    Write-Host ""

    # ── PATH ────────────────────────────────────────────────────────────────
    $pathScope = if (Test-IsAdmin) { 'Machine' } else { 'User' }
    Add-PathEntry -Value $BinDir -Scope $pathScope
    $env:Path = "$env:Path;$BinDir"

    # ── Ollama auto-install ─────────────────────────────────────────────────
    Install-Ollama

    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor Cyan
    Write-Host "  legion-web             # launch the dashboard (http://localhost:3000)"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
