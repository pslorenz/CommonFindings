# GPP cpassword in SYSVOL

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Trivial (one-line PowerShell)

## What it is

Group Policy Preferences (GPP), introduced in Server 2008, allowed admins to set local user passwords, mapped drive credentials, scheduled task credentials, and service credentials via GPO. The password was stored in the GPO XML in SYSVOL, encrypted with AES — except Microsoft published the AES key in MSDN. Anyone in the domain (SYSVOL is readable by all authenticated users) can decrypt these `cpassword` values trivially.

Microsoft removed the ability to set these passwords via GPP in 2014 (MS14-025). The patch prevents *creating* new ones but **does not remove existing ones**. Many environments still have decade-old `cpassword` entries sitting in SYSVOL, often containing local admin or domain service account credentials.

## What attack it enables

Any domain user retrieves credentials — frequently for local administrator or a privileged service account — and uses them for lateral movement or privilege escalation.

MITRE ATT&CK: T1552.006

## How to confirm it's present in your environment

```powershell
# Search SYSVOL on any DC for cpassword entries
Get-ChildItem -Path "\\$((Get-ADDomain).DNSRoot)\SYSVOL" -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml' -ErrorAction SilentlyContinue |
    Select-String -Pattern 'cpassword' |
    Select-Object Path, Line
```

If anything is returned, you have the problem.

To decrypt and see what credentials are exposed (you should know what's there before deciding remediation order):
```powershell
# Use the Get-GPPPassword function from the PowerSploit project, or Invoke-PowerView
# Or use SharpHound / GPP password module. Many freely available tools.
```

## What to audit before remediation

For each `cpassword` you find:
1. **Decrypt it.** What credential is it?
2. **Is the credential still in use?** Most are old and dormant — but assume it has been compromised regardless.
3. **What does it grant access to?** A local Administrator on workstations is a fleet-wide concern. A service account for a single legacy app is contained.

You'll also want to grep the actual XML to see what hosts/scopes the GPO applied to — that's the blast radius of what may already have been compromised.

## Remediation

**1. Rotate every credential found.** Assume each one is known to attackers — SYSVOL has been readable by all domain users for the entire time the file existed.

**2. Remove the cpassword entries.** Either delete the affected GPP setting via Group Policy Management Console (the MS14-025 patch prevents you from saving a new one with a password, so editing forces removal), or delete the GPO outright if no longer needed.

```powershell
# Identify the GPOs containing cpassword
$matches = Get-ChildItem -Path "\\$((Get-ADDomain).DNSRoot)\SYSVOL" -Recurse -Include '*.xml' |
    Select-String -Pattern 'cpassword'

# For each, get the GPO GUID from the path, then look up the GPO name
$matches | ForEach-Object {
    $guid = ($_.Path -split '\\')[6]  # adjust based on path structure
    Get-GPO -Guid $guid | Select-Object DisplayName, Id
}
```

**3. Replace the workflow.** What was the GPP credential being used for?
- **Setting local admin password**: deploy LAPS (see [`laps-not-deployed.md`](laps-not-deployed.md)).
- **Mapped drive with stored creds**: use Kerberos auth, or a service that doesn't require stored credentials.
- **Scheduled task / service running as a domain account**: use a gMSA.

## What might break

- Whatever the GPP setting was doing. If it set a local admin password, removing the GPO doesn't change the password that was already set — you'll need to set new passwords (use LAPS).
- Mapped drives or scheduled tasks defined via GPP will stop being created/maintained.

If the GPO is years old and no one documented what it was for, it's likely doing nothing useful today and the cleanup is purely beneficial.

## Rollback

Restore the GPO from backup if needed, but understand that the credential is already exposed and rotating it is non-negotiable.

## Validate the fix

```powershell
# Re-run the search; expect zero results
Get-ChildItem -Path "\\$((Get-ADDomain).DNSRoot)\SYSVOL" -Recurse -Include '*.xml' |
    Select-String -Pattern 'cpassword'
```

## References

- Microsoft: [MS14-025](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025)
- Microsoft: [Group Policy Preferences password disclosure](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/cve-2014-1812-group-policy-preferences)
- MITRE ATT&CK: T1552.006
