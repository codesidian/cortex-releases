# cortex-releases

Signed cortex-agent releases and their installers. This repository is the
source of truth for installing Cortex. codesidian.com only mirrors it
(`https://codesidian.com/releases/`), and `codesidian.com/cortex-agent`
redirects here, so a compromised codesidian.com can't change what a new
machine runs.

## Release key

Everything is signed by the release key on a YubiKey. Check that this matches
the key shown on the dashboard's Add device page and in `minisign.pub`:

```
key id     7B18C33C46C338CC
public key RWTMOMNGPMMYeyHWCdx4DV3efXIN/mUZ/4HpLKOV2bT5A7/L8uE3KBlr
```

`minisign-next.pub` (key id `BA4646D760FEF3FF`) is the backup key; a release
signed by either is valid.

## Install

### Linux (verified)

Needs [minisign](https://jedisct1.github.io/minisign/) (`apt install minisign`,
`dnf install minisign`, `brew install minisign`).

```bash
curl -fsSLO https://github.com/codesidian/cortex-releases/releases/latest/download/install.sh
curl -fsSLO https://github.com/codesidian/cortex-releases/releases/latest/download/install.sh.minisig
minisign -Vm install.sh -P RWTMOMNGPMMYeyHWCdx4DV3efXIN/mUZ/4HpLKOV2bT5A7/L8uE3KBlr || minisign -Vm install.sh -P RWT/8/5g10ZGuhRajdSupsEOmAJLihVNgACDUEOkFw6YP95QuLRcsyJ2
sudo bash install.sh --code <ENROLLMENT_CODE> --fingerprint <FINGERPRINT>
```

One of the two `minisign` runs must print `Signature and comment signature
verified` (the first key is the primary YubiKey, the second the backup; a
release may be signed by either, and the release notes name which). If neither
does, stop: the script is not the one a release key signed.

### Linux (quick)

```bash
curl -fsSL https://github.com/codesidian/cortex-releases/releases/latest/download/install.sh \
  | sudo bash -s -- --code <ENROLLMENT_CODE> --fingerprint <FINGERPRINT>
```

This skips the script check and trusts GitHub alone. The script still checks
the signature of everything it downloads.

### Windows (elevated PowerShell)

```powershell
irm https://github.com/codesidian/cortex-releases/releases/latest/download/install.ps1 -OutFile install.ps1
.\install.ps1 -Code <ENROLLMENT_CODE> -Fingerprint <FINGERPRINT>
```

To check `install.ps1` first (`winget install jedisct1.minisign`), verify the
signed manifest and compare the script's hash with the one it lists:

```powershell
foreach ($f in "manifest.json", "manifest.json.minisig") { irm "https://github.com/codesidian/cortex-releases/releases/latest/download/$f" -OutFile $f }
minisign -Vm manifest.json -P RWTMOMNGPMMYeyHWCdx4DV3efXIN/mUZ/4HpLKOV2bT5A7/L8uE3KBlr   # or the backup key RWT/8/5g10ZGuhRajdSupsEOmAJLihVNgACDUEOkFw6YP95QuLRcsyJ2
(Get-FileHash install.ps1).Hash.ToLower() -eq (Get-Content -Raw manifest.json | ConvertFrom-Json).installers.'install.ps1'.sha256
```

### Options

A new machine gets a local command policy before it enrolls: `read-only` by
default (no terminal, no scheduled jobs, files read-only). Pick another with
`--policy` / `-Policy` (`read-only`, `monitor-only`, `full`). An existing policy
is kept. Change it later on the machine itself:
`cortex-agent policy init --preset full --force`.

`--base` / `-Base` also accepts a flat mirror directory (`manifest.json` and the
binaries side by side), such as `https://codesidian.com/releases`. The
installer still checks the mirror's manifest signature against the keys pinned
in the (verified) script.

## Verify a release

```bash
minisign -Vm manifest.json -p minisign.pub   # or minisign-next.pub (backup key)
minisign -Vm install.sh -p minisign.pub
sha256sum cortex-agent-* install.sh install.ps1   # compare with manifest.json
```

## Publish

Releases are built by `codesidian/cortex-agent`'s `release` workflow from a
`v*` tag and land here as a **draft**, with the installers from this
repository's `main` attached and listed in `manifest.json`. The owner reviews
the draft and signs `manifest.json` and `install.sh` with the release YubiKey,
which publishes it:

```
python sign-release.py v0.1.10      # codesidian-infra/release/
```

On publish, `floor` opens a PR raising the installers' `MIN_VERSION` and `verify`
re-checks the release against the pinned keys (also daily).
