# RE-super-agent install script (Windows / PowerShell).
# Usage:
#   ./install.ps1 core   # minimal: Python deps + YARA + Docker image (core)
#   ./install.ps1 full   # everything: + Ghidra, angr, Frida, x64dbg/WinDbg, capa
#   ./install.ps1 check  # report availability
[CmdletBinding()]
param([Parameter(Position=0)][string]$Tier = "core")
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Info($m){ Write-Host "[i] $m" -ForegroundColor Cyan }
function OK($m){   Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m){  Write-Host "[x] $m" -ForegroundColor Red }

function Have($c){ return [bool](Get-Command $c -ErrorAction SilentlyContinue) }

function Check-Tools{
  Info "Checking tool availability:"
  $tools = @("python","pip","git","yara","frida","docker")
  $missing = @()
  foreach($t in $tools){ if(Have $t){ OK "found: $t" } else { Warn "missing: $t"; $missing += $t } }
  if($missing.Count -eq 0){ OK "all checked tools present." } else { Warn "missing: $($missing -join ', ')" }
}

function Build-Docker($tier){
  if(Have "docker"){
    Info "Building re-agent:$tier sandbox image ..."
    docker build --target $tier -t "re-agent:$tier" -f Dockerfile .
    if($LASTEXITCODE -ne 0){ Warn "Docker build failed; sandbox dynamic exec unavailable." }
  } else {
    Warn "docker not found; sandbox will run static-only fallback. Install Docker Desktop to enable dynamic exec."
  }
}

function Install-Core{
  Info "Installing core (Python deps + YARA + Docker core image)."
  python -m pip install -e ".[dev]"
  if(-not (Have "yara")){ Warn "Install YARA from https://virustotal.github.io/yara/ (yara-python wheel bundles engine)." }
  Build-Docker core
}

function Install-Full{
  Install-Core
  Info "Installing full RE stack (Ghidra, angr, Frida, debuggers, capa)."
  python -m pip install -e ".[full]"
  if(-not (Have "ghidraRun")){
    Warn "Install Ghidra from https://github.com/NationalSecurityAgency/ghidra/releases (needs JDK); set engines.ghidra.install_path."
  }
  Warn "Windows debuggers: x64dbg (GUI fallback) or WinDbg (pykd backend). Install separately."
  python -m pip install capa
  Build-Docker full
}

switch($Tier){
  "core"  { Install-Core }
  "full"  { Install-Full }
  "check" { Check-Tools }
  default { Err "Usage: ./install.ps1 {core|full|check}"; exit 1 }
}
OK "Done ($Tier)."
