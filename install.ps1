<#
.SYNOPSIS
  Codesidian cortex-agent installer (Windows).

.DESCRIPTION
  Downloads the signed cortex-agent release for this machine, verifies its
  integrity against the signed release manifest, installs it to Program Files +
  PATH, then enrolls it (which also installs + starts the Windows service).

  Run from an elevated (Administrator) PowerShell:

    irm https://raw.githubusercontent.com/codesidian/cortex-releases/main/install.ps1 -OutFile install.ps1
    notepad install.ps1
    .\install.ps1 -Code <ENROLLMENT_CODE> -Fingerprint <USER_KEY_FINGERPRINT>

.NOTES
  SECURITY: the release manifest is signed with an offline Ed25519 key whose
  public half is embedded in the agent. The binary is bound to that signed
  manifest by SHA-256 (fetched over TLS); after install we run
  `cortex-agent verify`, which re-checks the signature with the embedded key.
  The -Fingerprint is the CR-1 trust anchor for your USER key and is only passed
  through to `enroll`; confirm it matches the dashboard.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Code,
  [Parameter(Mandatory = $true)][string]$Fingerprint,
  [string]$ApiUrl,
  [switch]$Dev,
  [string]$Base = "https://github.com/codesidian/cortex-releases/releases"
)

$ErrorActionPreference = "Stop"
function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m){   Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m){  Write-Host "[x] $m" -ForegroundColor Red; exit 1 }

# --- elevation check ---------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal] `
  [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  Die "Administrator privileges required (install to Program Files + service). Re-run in an elevated PowerShell."
}

# --- target detection (x64 only at present) ----------------------------------
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
  Die "unsupported architecture: $arch (x64 only at present)"
}
$Target = "x86_64-pc-windows-msvc"
Info "Target: $Target"

$tmp = Join-Path $env:TEMP ("cortex-agent-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  # --- fetch + parse manifest ------------------------------------------------
  Info "Fetching release manifest ..."
  $manifestPath = Join-Path $tmp "manifest.json"
  $sigPath      = Join-Path $tmp "manifest.json.minisig"
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/latest/download/manifest.json"         -OutFile $manifestPath
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/latest/download/manifest.json.minisig" -OutFile $sigPath

  $manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
  $entry = $manifest.targets.$Target
  if (-not $entry) { Die "no release artifact for $Target in manifest (not built yet?)" }
  $file    = $entry.file
  $wantSha = $entry.sha256
  Info ("Latest version: {0} ({1})" -f $manifest.version, $file)

  # --- download + integrity check --------------------------------------------
  Info "Downloading $file ..."
  $binPath = Join-Path $tmp "cortex-agent.exe"
  if ($file -match '[\\/]' -or $file -match '\.\.') { Die "unsafe artifact name in manifest: $file" }
  Invoke-WebRequest -UseBasicParsing -Uri ("$Base/download/v{0}/{1}" -f $manifest.version, $file) -OutFile $binPath
  $gotSha = (Get-FileHash -Algorithm SHA256 $binPath).Hash.ToLower()
  if ($gotSha -ne $wantSha.ToLower()) {
    Die "SHA-256 mismatch (expected $wantSha, got $gotSha) - refusing to install"
  }
  Ok "SHA-256 verified against signed manifest"

  # Defence in depth: freshly-downloaded agent re-verifies the manifest
  # signature with its embedded release key before we trust it.
  & $binPath verify --manifest $manifestPath --signature $sigPath --binary $binPath --target $Target | Out-Null
  if ($LASTEXITCODE -ne 0) { Die "agent signature self-check FAILED - refusing to install" }
  Ok "release signature verified by the agent (embedded key)"

  # --- install ---------------------------------------------------------------
  $installDir = Join-Path $env:ProgramFiles "Codesidian"
  $installPath = Join-Path $installDir "cortex-agent.exe"
  Info "Installing to $installPath ..."
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  Copy-Item -Force $binPath $installPath
  Ok ("installed cortex-agent {0}" -f $manifest.version)

  # add install dir to system PATH if missing
  $sysPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  if ($sysPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$sysPath;$installDir", "Machine")
    $env:Path = "$env:Path;$installDir"
    Ok "added $installDir to system PATH"
  }

  # --- enroll (installs + starts the service) --------------------------------
  Info "Enrolling agent ..."
  $enrollArgs = @()
  if ($Dev) { $enrollArgs += "--dev" }
  $enrollArgs += @("enroll", "--code", $Code, "--fingerprint", $Fingerprint)
  if ($ApiUrl) { $enrollArgs += @("--api-url", $ApiUrl) }
  & $installPath @enrollArgs
  if ($LASTEXITCODE -ne 0) { Die "enrollment failed" }

  Ok "Done. The cortex-agent is installed, enrolled, and running as a service."
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
