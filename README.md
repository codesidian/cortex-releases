# cortex-releases

## Install

Linux:

```bash
curl -fsSL -o install.sh https://raw.githubusercontent.com/codesidian/cortex-releases/main/install.sh
sudo bash install.sh --code <ENROLLMENT_CODE> --fingerprint <FINGERPRINT>
```

Windows (elevated PowerShell):

```powershell
irm https://raw.githubusercontent.com/codesidian/cortex-releases/main/install.ps1 -OutFile install.ps1
.\install.ps1 -Code <ENROLLMENT_CODE> -Fingerprint <FINGERPRINT>
```

A new machine gets a local command policy before it enrolls: `read-only` by
default (no terminal, no scheduled jobs, files read-only). Pick another with
`--policy` / `-Policy` (`read-only`, `monitor-only`, `full`). An existing policy
is kept. Change it later on the machine itself:
`cortex-agent policy init --preset full --force`.

`--base` / `-Base` also accepts a flat mirror directory (`manifest.json` and the
binaries side by side), such as `https://codesidian.com/releases`.

## Verify

```bash
minisign -Vm manifest.json -p minisign.pub   # or minisign-next.pub (backup key)
sha256sum cortex-agent-*   # compare with manifest.json
```

## Publish

Releases are built by `codesidian/cortex-agent`'s `release` workflow from a
`v*` tag and land here as a **draft**. The owner reviews and signs the draft's
`manifest.json` with the release YubiKey, which publishes it:

```
python sign-release.py v0.1.8      # codesidian-infra/release/
```

On publish, `floor` opens a PR raising the installers' `MIN_VERSION` and `verify`
re-checks the release against the pinned keys (also daily).
