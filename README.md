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

## Verify

```bash
minisign -Vm manifest.json -p minisign.pub
sha256sum cortex-agent-*   # compare with manifest.json
```

## Publish

```bash
scripts/publish.sh <release-dir>   # manifest.json, manifest.json.minisig, binaries
```
