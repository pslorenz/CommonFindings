# SMBv1 Enabled

**Category:** Network Services (also Legacy)
**Operational Risk of Remediation:** Medium
**Attacker Skill Required to Exploit:** Low (EternalBlue is a Metasploit module)

## What it is

SMB version 1, designed in the 1980s, has well-known unauthenticated remote code execution vulnerabilities, most famously EternalBlue (MS17-010), which fueled WannaCry and NotPetya. Microsoft has marked SMBv1 deprecated and removed it from default installs since Windows 10 1709 / Server 2019, but it persists on upgraded systems and on appliances.

## What attack it enables

- Unauthenticated RCE (EternalBlue and friends) on any unpatched Windows host with SMBv1 listening.
- Even on patched hosts, SMBv1 has no signing or encryption, making it a trivial relay/MitM target.
- Worm propagation. WannaCry-style outbreaks specifically required SMBv1.

## How to confirm it's present in your environment

```powershell
# On a single host
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
# State : Enabled = bad

# Server SMB config — check both server and client
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Get-SmbClientConfiguration | Select-Object EnableSMB1Protocol
```

At scale, audit which hosts have SMBv1 *clients* connecting:
```powershell
# On each file server:
Set-SmbServerConfiguration -AuditSmb1Access $true -Confirm:$false
# Then watch:
Get-WinEvent -LogName Microsoft-Windows-SMBServer/Audit |
    Where-Object { $_.Id -eq 3000 } |
    Select-Object TimeCreated, @{N='Client';E={$_.Properties[0].Value}}
```

`Event ID 3000` in `Microsoft-Windows-SMBServer/Audit` = a client connected using SMBv1. Run for 2 weeks minimum.

## What to audit before remediation

This is the audit you cannot skip. Common SMBv1 holdouts:
- Old NAS devices (older Synology, QNAP, NetApp, EMC firmware)
- Old Linux Samba (Samba 3.x)
- Multi-function printers using "Scan to SMB" with old firmware
- Industrial / SCADA / medical devices
- Windows XP, Windows Server 2003 (which should not exist in your environment, but…)
- Some macOS versions <10.9 (also should not exist)

For each Event ID 3000, look up the client IP. Either upgrade the client to support SMB2/3 or replace it. Vendor firmware updates exist for most modern devices.

## Remediation

**Disable SMBv1 server (host stops accepting SMBv1 connections):**
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
# Or via PowerShell direct:
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
```

**Disable SMBv1 client (host stops being able to connect *to* SMBv1 servers):**
```powershell
sc.exe config mrxsmb10 start= disabled
sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
```

**At scale via GPO** — use the Microsoft Security Baseline GPO, or:
- Computer Configuration → Preferences → Windows Settings → Registry → set `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 0 (DWORD)`

Reboot required.

For Linux Samba: `min protocol = SMB2` in `[global]` of `smb.conf`.

## What might break

- Anything in the audit list above that you missed. Symptom: "cannot access \\server\share" with no clear error, or appliances silently failing to scan/backup.
- WMI queries from old management tools.
- Some old endpoint backup agents.

If your audit log is clean, breakage is near zero. If you skipped the audit, expect surprises.

## Rollback

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
sc.exe config mrxsmb10 start= auto
```
Reboot. Old clients reconnect.

## Validate the fix

```powershell
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
# False
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
# State : Disabled
```

```bash
nmap -p445 --script smb-protocols <host>
# Should list SMBv2 and SMBv3, not SMBv1
```

## References

- Microsoft: [SMBv1 is not installed by default in Windows](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows)
- Microsoft: [Stop using SMB1](https://techcommunity.microsoft.com/blog/storageatmicrosoft/stop-using-smb1/425858) — Ned Pyle's classic post
- MITRE ATT&CK: T1210
