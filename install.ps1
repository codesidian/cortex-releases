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
  SECURITY: the release manifest is signed with an offline Ed25519 (minisign)
  key. Its public half is pinned in this script ($ReleasePubkeys) and the
  signature is checked here BEFORE anything downloaded is executed, so a
  tampered manifest or binary on the release host is refused. The binary is
  then bound to the verified manifest by SHA-256, and `cortex-agent verify`
  re-checks the signature with the agent's embedded key as defence in depth.
  This only helps if this script itself comes from somewhere the release host
  can't modify; read it before running it.
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
# throw, not exit: the dashboard one-liner runs this as a scriptblock in the
# user's own session, where exit closes the PowerShell window before the
# error can be read. A throw still fails `powershell -File` with exit code 1.
function Die($m){  Write-Host "[x] $m" -ForegroundColor Red; throw "cortex-agent install failed: $m" }

# Rollback floor: refuse any signed release older than this. Raised together
# with install.sh's MIN_VERSION by .github/workflows/floor.yml.
$MinVersion = "0.1.7"

# Trusted release signing keys (minisign public key lines). Must match
# RELEASE_PUBKEYS in install.sh and RELEASE_PUBKEY_CURRENT / RELEASE_PUBKEY_NEXT
# in cortex-agent/src/release_trust.rs.
$ReleasePubkeys = @(
  "RWTMOMNGPMMYeyHWCdx4DV3efXIN/mUZ/4HpLKOV2bT5A7/L8uE3KBlr",
  "RWT/8/5g10ZGuhRajdSupsEOmAJLihVNgACDUEOkFw6YP95QuLRcsyJ2"
)

# GitHub needs TLS 1.2, which Windows PowerShell 5.1 may not enable by default;
# the progress bar makes its downloads crawl.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$ProgressPreference = "SilentlyContinue"

# minisign verification (Ed25519 + BLAKE2b-512) in C#, since .NET has neither
# built in. Compiled once per session; Windows PowerShell 5.1 needs the
# System.Numerics reference for BigInteger.
$minisignSource = @'
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public static class CortexMinisignV1
{
    static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    static readonly BigInteger L = BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");
    static readonly BigInteger D = Mod(-121665 * Inv(121666));
    static readonly BigInteger I = BigInteger.ModPow(2, (P - 1) / 4, P);

    static BigInteger Mod(BigInteger a) { BigInteger r = a % P; return r.Sign < 0 ? r + P : r; }
    static BigInteger Inv(BigInteger a) { return BigInteger.ModPow(a, P - 2, P); }

    static BigInteger FromLE(byte[] b, int off, int len)
    {
        byte[] t = new byte[len + 1];
        Array.Copy(b, off, t, 0, len);
        return new BigInteger(t);
    }

    // Extended coordinates (X, Y, Z, T), RFC 8032 section 5.1.4.
    static BigInteger[] Add(BigInteger[] p, BigInteger[] q)
    {
        BigInteger a = Mod((p[1] - p[0]) * (q[1] - q[0]));
        BigInteger b = Mod((p[1] + p[0]) * (q[1] + q[0]));
        BigInteger c = Mod(2 * p[3] * q[3] * D);
        BigInteger d = Mod(2 * p[2] * q[2]);
        BigInteger e = b - a, f = d - c, g = d + c, h = b + a;
        return new BigInteger[] { Mod(e * f), Mod(g * h), Mod(f * g), Mod(e * h) };
    }

    static BigInteger[] Mul(BigInteger s, BigInteger[] p)
    {
        BigInteger[] q = { 0, 1, 1, 0 };
        while (s > 0)
        {
            if (!s.IsEven) q = Add(q, p);
            p = Add(p, p);
            s >>= 1;
        }
        return q;
    }

    static BigInteger[] Decode(byte[] b)
    {
        if (b.Length != 32) return null;
        int sign = b[31] >> 7;
        byte[] t = (byte[])b.Clone();
        t[31] &= 0x7f;
        BigInteger y = FromLE(t, 0, 32);
        if (y >= P) return null;
        BigInteger x2 = Mod((y * y - 1) * Inv(D * y * y + 1));
        BigInteger x = BigInteger.ModPow(x2, (P + 3) / 8, P);
        if (Mod(x * x - x2) != 0) x = Mod(x * I);
        if (Mod(x * x - x2) != 0) return null;
        if (x.IsZero && sign == 1) return null;
        if ((int)(x % 2) != sign) x = P - x;
        return new BigInteger[] { x, y, 1, Mod(x * y) };
    }

    static byte[] Encode(BigInteger[] p)
    {
        BigInteger zi = Inv(p[2]);
        BigInteger x = Mod(p[0] * zi), y = Mod(p[1] * zi);
        byte[] raw = y.ToByteArray();
        byte[] o = new byte[32];
        Array.Copy(raw, o, Math.Min(raw.Length, 32));
        if (!x.IsEven) o[31] |= 0x80;
        return o;
    }

    static readonly BigInteger[] B = Decode(new byte[] {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66 });

    // Ed25519 verification (RFC 8032), cofactorless like libsodium: [S]B - [h]A must encode to R.
    public static bool Ed25519Verify(byte[] pk, byte[] msg, byte[] sig)
    {
        if (pk == null || pk.Length != 32 || sig == null || sig.Length != 64) return false;
        BigInteger[] a = Decode(pk);
        if (a == null) return false;
        BigInteger s = FromLE(sig, 32, 32);
        if (s >= L) return false;
        byte[] h;
        using (SHA512 sha = SHA512.Create())
        {
            byte[] buf = new byte[64 + msg.Length];
            Array.Copy(sig, 0, buf, 0, 32);
            Array.Copy(pk, 0, buf, 32, 32);
            Array.Copy(msg, 0, buf, 64, msg.Length);
            h = sha.ComputeHash(buf);
        }
        BigInteger k = FromLE(h, 0, 64) % L;
        BigInteger[] negA = { Mod(-a[0]), a[1], a[2], Mod(-a[3]) };
        byte[] r = Encode(Add(Mul(s, B), Mul(k, negA)));
        int diff = 0;
        for (int i = 0; i < 32; i++) diff |= r[i] ^ sig[i];
        return diff == 0;
    }

    static readonly ulong[] IV = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL };
    static readonly byte[,] Sigma = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 } };

    static ulong Rotr(ulong x, int n) { return (x >> n) | (x << (64 - n)); }

    static void G(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
    {
        unchecked
        {
            v[a] = v[a] + v[b] + x; v[d] = Rotr(v[d] ^ v[a], 32);
            v[c] = v[c] + v[d];     v[b] = Rotr(v[b] ^ v[c], 24);
            v[a] = v[a] + v[b] + y; v[d] = Rotr(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];     v[b] = Rotr(v[b] ^ v[c], 63);
        }
    }

    // Unkeyed BLAKE2b-512 (RFC 7693), minisign's prehash.
    public static byte[] Blake2b512(byte[] data)
    {
        ulong[] h = (ulong[])IV.Clone();
        h[0] ^= 0x01010040UL;
        ulong[] m = new ulong[16], v = new ulong[16];
        int blocks = Math.Max(1, (data.Length + 127) / 128);
        for (int n = 0; n < blocks; n++)
        {
            byte[] block = new byte[128];
            int off = n * 128, len = Math.Min(128, data.Length - off);
            if (len > 0) Array.Copy(data, off, block, 0, len);
            for (int i = 0; i < 16; i++) m[i] = BitConverter.ToUInt64(block, i * 8);
            ulong t = (ulong)(off + Math.Max(len, 0));
            Array.Copy(h, v, 8);
            Array.Copy(IV, 0, v, 8, 8);
            v[12] ^= t;
            if (n == blocks - 1) v[14] = ~v[14];
            for (int r = 0; r < 12; r++)
            {
                int s = r % 10;
                G(v, 0, 4, 8, 12, m[Sigma[s, 0]], m[Sigma[s, 1]]);
                G(v, 1, 5, 9, 13, m[Sigma[s, 2]], m[Sigma[s, 3]]);
                G(v, 2, 6, 10, 14, m[Sigma[s, 4]], m[Sigma[s, 5]]);
                G(v, 3, 7, 11, 15, m[Sigma[s, 6]], m[Sigma[s, 7]]);
                G(v, 0, 5, 10, 15, m[Sigma[s, 8]], m[Sigma[s, 9]]);
                G(v, 1, 6, 11, 12, m[Sigma[s, 10]], m[Sigma[s, 11]]);
                G(v, 2, 7, 8, 13, m[Sigma[s, 12]], m[Sigma[s, 13]]);
                G(v, 3, 4, 9, 14, m[Sigma[s, 14]], m[Sigma[s, 15]]);
            }
            for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
        }
        byte[] o = new byte[64];
        for (int i = 0; i < 8; i++) Array.Copy(BitConverter.GetBytes(h[i]), 0, o, i * 8, 8);
        return o;
    }

    // Verify a minisign signature file over data against base64 minisign public
    // keys: the signature over the file (prehashed "ED" or legacy "Ed") and the
    // global signature over signature || trusted comment.
    public static bool Verify(byte[] data, string sigText, string[] pubkeys)
    {
        try
        {
            string[] lines = sigText.Replace("\r", "").Split('\n');
            if (lines.Length < 4 || !lines[2].StartsWith("trusted comment: ", StringComparison.Ordinal)) return false;
            byte[] blob = Convert.FromBase64String(lines[1]);
            byte[] gsig = Convert.FromBase64String(lines[3]);
            if (blob.Length != 74 || gsig.Length != 64) return false;
            string alg = Encoding.ASCII.GetString(blob, 0, 2);
            byte[] msg;
            if (alg == "ED") msg = Blake2b512(data);
            else if (alg == "Ed") msg = data;
            else return false;
            byte[] sig = new byte[64];
            Array.Copy(blob, 10, sig, 0, 64);
            byte[] tc = Encoding.UTF8.GetBytes(lines[2].Substring("trusted comment: ".Length));
            byte[] gmsg = new byte[64 + tc.Length];
            Array.Copy(sig, gmsg, 64);
            Array.Copy(tc, 0, gmsg, 64, tc.Length);
            foreach (string k in pubkeys)
            {
                byte[] pk = Convert.FromBase64String(k);
                if (pk.Length != 42 || pk[0] != (byte)'E' || pk[1] != (byte)'d') continue;
                bool idMatch = true;
                for (int i = 2; i < 10; i++) if (pk[i] != blob[i]) idMatch = false;
                if (!idMatch) continue;
                byte[] key = new byte[32];
                Array.Copy(pk, 10, key, 0, 32);
                if (Ed25519Verify(key, msg, sig) && Ed25519Verify(key, gmsg, gsig)) return true;
            }
        }
        catch (FormatException) { }
        return false;
    }
}
'@
if (-not ("CortexMinisignV1" -as [type])) {
  if ($PSVersionTable.PSEdition -eq "Desktop") {
    Add-Type -TypeDefinition $minisignSource -ReferencedAssemblies System.Numerics
  } else {
    Add-Type -TypeDefinition $minisignSource
  }
}

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
  # --- fetch + verify manifest -----------------------------------------------
  Info "Fetching release manifest ..."
  $manifestPath = Join-Path $tmp "manifest.json"
  $sigPath      = Join-Path $tmp "manifest.json.minisig"
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/latest/download/manifest.json"         -OutFile $manifestPath
  Invoke-WebRequest -UseBasicParsing -Uri "$Base/latest/download/manifest.json.minisig" -OutFile $sigPath

  # Verify and parse the same bytes, so nothing can swap the file in between.
  $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
  $sigText = [IO.File]::ReadAllText($sigPath)
  if (-not [CortexMinisignV1]::Verify($manifestBytes, $sigText, $ReleasePubkeys)) {
    Die "release manifest signature does not match the pinned release key; refusing to install"
  }
  Ok "Release manifest signature verified (pinned key)"

  $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
  $version = [string]$manifest.version
  if ($version -notmatch '^\d+\.\d+\.\d+$') { Die "bad version in manifest: $version" }
  if ([version]$version -lt [version]$MinVersion) {
    Die "release $version is older than this installer's floor $MinVersion; refusing (possible rollback)"
  }
  if ($manifest.expires) {
    # PowerShell 7's ConvertFrom-Json already turns it into a DateTime; 5.1 leaves a string.
    if ($manifest.expires -is [DateTime]) { $expires = [DateTimeOffset]$manifest.expires.ToUniversalTime() }
    else { $expires = [DateTimeOffset]::Parse([string]$manifest.expires, [Globalization.CultureInfo]::InvariantCulture) }
    if ([DateTimeOffset]::UtcNow -gt $expires) {
      Die "release manifest expired at $($manifest.expires); refusing (possible stale mirror)"
    }
  }
  $entry = $manifest.targets.$Target
  if (-not $entry) { Die "no release artifact for $Target in manifest (not built yet?)" }
  $file    = [string]$entry.file
  $wantSha = ([string]$entry.sha256).ToLower()
  if ($file -notmatch '^[A-Za-z0-9._-]+$' -or $file -match '\.\.') { Die "unsafe artifact name in manifest: $file" }
  if ($wantSha -notmatch '^[0-9a-f]{64}$') { Die "bad sha256 in manifest for $Target" }
  Info ("Latest version: {0} ({1})" -f $version, $file)

  # --- download + integrity check --------------------------------------------
  # Staged inside the admin-only install dir, not %TEMP%, so a non-elevated
  # process can't swap the binary between the hash check and running it.
  $installDir = Join-Path $env:ProgramFiles "Codesidian"
  $installPath = Join-Path $installDir "cortex-agent.exe"
  # Must end in .exe: PowerShell hands any other extension to the shell as a
  # document ("Cannot run a document in the middle of a pipeline").
  $stagePath = Join-Path $installDir "cortex-agent.download.exe"
  New-Item -ItemType Directory -Force -Path $installDir | Out-Null
  # Left behind by installers before this fix.
  Remove-Item -Force (Join-Path $installDir "cortex-agent.exe.download") -ErrorAction SilentlyContinue
  Info "Downloading $file ..."
  Invoke-WebRequest -UseBasicParsing -Uri ("$Base/download/v{0}/{1}" -f $version, $file) -OutFile $stagePath
  $gotSha = (Get-FileHash -Algorithm SHA256 $stagePath).Hash.ToLower()
  if ($gotSha -ne $wantSha) {
    Remove-Item -Force $stagePath -ErrorAction SilentlyContinue
    Die "SHA-256 mismatch (expected $wantSha, got $gotSha) - refusing to install"
  }
  Ok "SHA-256 verified against signed manifest"

  # Defence in depth: the agent re-verifies the manifest signature with its
  # embedded release key.
  & $stagePath verify --manifest $manifestPath --signature $sigPath --binary $stagePath --target $Target | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -Force $stagePath -ErrorAction SilentlyContinue
    Die "agent signature self-check FAILED - refusing to install"
  }
  Ok "release signature verified by the agent (embedded key)"

  # --- install ---------------------------------------------------------------
  Info "Installing to $installPath ..."
  Move-Item -Force $stagePath $installPath
  Ok ("installed cortex-agent {0}" -f $version)

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
