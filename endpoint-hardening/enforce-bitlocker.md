# BitLocker Not Enforced

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Low (on modern hardware with TPM)
**Attacker Skill Required to Exploit:** Physical access (stolen/lost device)

## What it is

Without full-disk encryption, anyone with physical access to a device can:
- Boot from a USB drive and read the entire filesystem.
- Remove the hard drive, mount it in another machine, and copy all files.
- Extract the local SAM database (local account hashes), cached domain credentials (DCC2 hashes), DPAPI secrets, browser saved passwords, and any files on disk including documents, code, and configuration files with embedded credentials.

BitLocker encrypts the entire volume transparently using AES-128 or AES-256. With a TPM (Trusted Platform Module), the user experiences no friction — the TPM unseals the encryption key automatically at boot after verifying the boot chain integrity.

This matters for laptops (which get lost, stolen, or left in airports) but also for servers and desktops (which get decommissioned without proper disk wiping, or are in physically accessible locations).

## What attack it enables (without the fix)

- Physical theft → full data access.
- Evil maid attack → boot from USB, extract credentials, return device.
- Decommissioned hardware → data recovery from unwiped drives.
- DMA attacks via Thunderbolt/PCIe on unlocked, unencrypted systems (mitigated by BitLocker + Kernel DMA Protection).

MITRE ATT&CK: T1005 (Data from Local System), T1552.001 (Credentials In Files)

## How to confirm it's not enabled

```powershell
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus, KeyProtector
# VolumeStatus should be FullyEncrypted
# ProtectionStatus should be On
# KeyProtector should include Tpm (or TpmPin for enhanced security)
```

At scale:
```powershell
# MBAM or Intune compliance reports show BitLocker status fleet-wide
# Or via AD, if BitLocker recovery keys are stored in AD:
Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase 'DC=example,DC=local' -Properties msFVE-RecoveryPassword |
    Group-Object { ($_.DistinguishedName -split ',')[1] } | Sort-Object Count -Descending
# Hosts with NO recovery info in AD = likely not encrypted
```

## What to audit before remediation

**Hardware requirements:**
- TPM 1.2 or 2.0. All business-class hardware since ~2015 has one. Run `Get-Tpm` to verify.
- UEFI firmware (BitLocker works with legacy BIOS but TPM auto-unlock requires UEFI).
- If no TPM: BitLocker can use a USB startup key or password, but this adds user friction. Not recommended for fleet deployment.

**Recovery key management is critical.** Before enabling BitLocker at scale, ensure recovery keys are backed up to:
- Active Directory (GPO setting, see remediation).
- Or Azure AD / Intune for cloud-managed devices.
- Or MBAM (Microsoft BitLocker Administration and Monitoring).

Without recovery key backup, a TPM failure, BIOS update, or Secure Boot change will lock the user out permanently.

**Performance:** BitLocker with AES-128 on hardware with AES-NI (any modern CPU) has negligible performance impact, benchmarks consistently show <2% overhead. SSDs show even less impact than HDDs.

## Remediation

**Step 1: Ensure recovery keys are stored in AD.**

GPO:
`Computer Configuration → Policies → Administrative Templates → Windows Components → BitLocker Drive Encryption → Operating System Drives`
- `Choose how BitLocker-protected operating system drives can be recovered = Enabled`
  - Check: `Save BitLocker recovery information to AD DS for operating system drives`
  - Select: `Store recovery passwords and key packages`
  - Check: `Do not enable BitLocker until recovery information is stored in AD DS`

**Step 2: Configure encryption settings.**

Same GPO path:
- `Require additional authentication at startup = Enabled`
  - Select: `Allow BitLocker without a compatible TPM` = unchecked (require TPM)
  - Or for higher security: `Require startup PIN with TPM`
- `Choose drive encryption method and cipher strength`
  - OS drives: `XTS-AES 256-bit` (Windows 10 1511+)
  - Fixed data drives: `XTS-AES 256-bit`
  - Removable drives: `AES-CBC 256-bit` (for cross-platform compatibility)

**Step 3: Enable BitLocker.**

Via Intune: create an Endpoint Protection profile with BitLocker settings. Encryption starts silently.

Via GPO + script:
```powershell
# Enable BitLocker with TPM protector and store recovery key in AD
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector
# Add TPM protector
Add-BitLockerKeyProtector -MountPoint "C:" -TpmProtector
# Backup to AD
Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId (Get-BitLockerVolume -MountPoint "C:").KeyProtector[0].KeyProtectorId
```

**Step 4: Verify recovery key storage.**
```powershell
# On the DC
Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase (Get-ADComputer <hostname>).DistinguishedName -Properties msFVE-RecoveryPassword
```

## What might break

- **BIOS/firmware updates** that change the boot chain may trigger BitLocker recovery (the TPM detects a change and refuses to unseal). Warn users to suspend BitLocker before BIOS updates: `Suspend-BitLocker -MountPoint "C:" -RebootCount 1`.
- **Dual-boot systems** - BitLocker on the Windows volume may interfere with other OS boot loaders.
- **Disk cloning / imaging** workflows - encrypted disks cannot be imaged with traditional tools. Use BitLocker-aware imaging (SCCM task sequence, or decrypt before imaging).
- **Hardware failures** (motherboard replacement, TPM failure) - the user enters the recovery key. If recovery keys aren't backed up, data is lost. This is why Step 1 is non-negotiable.

## Rollback

```powershell
Disable-BitLocker -MountPoint "C:"
# Decryption begins in the background. Takes 30–120 min depending on drive size.
```

## Validate the fix

```powershell
Get-BitLockerVolume -MountPoint "C:" | Select-Object VolumeStatus, ProtectionStatus, EncryptionMethod
# FullyEncrypted, On, XtsAes256
```

Verify recovery key is in AD:
```powershell
# On DC
Get-ADObject -Filter 'objectClass -eq "msFVE-RecoveryInformation"' -SearchBase (Get-ADComputer <hostname>).DistinguishedName
# Should return at least one recovery information object
```

## References

- Microsoft: [BitLocker overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/)
- Microsoft: [BitLocker Group Policy settings](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-group-policy-settings)
- Microsoft: [BitLocker recovery guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/bitlocker-recovery-guide-plan)
- MITRE ATT&CK: T1005, T1552.001
