# Stale Accounts and Password Hygiene

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low (with reasonable verification)
**Attacker Skill Required to Exploit:** Trivial

## What it is

Active Directory accumulates accounts that no longer correspond to active users or systems:

- **Users who left the company** but the account was disabled-only, never deleted, and may have been re-enabled by mistake or never disabled at all.
- **Computer accounts** for systems decommissioned years ago.
- **Service accounts** for retired applications.
- **Accounts with passwords that have not changed in years** — including service accounts that may now have weak hashes or be on long-since-leaked password lists.
- **Accounts flagged `PasswordNotRequired`** — they can have an empty password.
- **Accounts flagged `PasswordNeverExpires`** — bypass the rotation policy.

Each of these is a target. The disabled employee account that someone "temporarily" re-enabled is the textbook example in IR reports.

## What attack it enables

- Password spray against accounts no one is monitoring (no one notices the lockout because no one uses them).
- Lateral movement using credentials of accounts no one would investigate.
- Long-term persistence (an attacker creates or re-enables a "service" account, no one ever audits it).

MITRE ATT&CK: T1078, T1136

## How to confirm it's present in your environment

```powershell
# Users with no logon in the last 90 days (still enabled)
$cutoff = (Get-Date).AddDays(-90)
Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate, Description |
    Where-Object { $_.LastLogonDate -lt $cutoff -or -not $_.LastLogonDate } |
    Select-Object SamAccountName, LastLogonDate, Description |
    Sort-Object LastLogonDate

# Computers with no logon in 90 days (still enabled)
Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate, OperatingSystem |
    Where-Object { $_.LastLogonDate -lt $cutoff -or -not $_.LastLogonDate } |
    Select-Object Name, LastLogonDate, OperatingSystem

# Users where password hasn't changed in over a year
$pwCutoff = (Get-Date).AddDays(-365)
Get-ADUser -Filter { Enabled -eq $true } -Properties PasswordLastSet |
    Where-Object { $_.PasswordLastSet -lt $pwCutoff } |
    Select-Object SamAccountName, PasswordLastSet |
    Sort-Object PasswordLastSet

# Accounts with PasswordNotRequired (can have empty password!)
Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } |
    Select-Object SamAccountName

# Accounts with PasswordNeverExpires (review whether justified)
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet

# Reversibly-encrypted passwords (very bad, password is recoverable as plaintext)
Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } |
    Select-Object SamAccountName
```

**Important LastLogonDate caveat:** `LastLogonDate` is replicated from `LastLogonTimestamp`, which only updates when the difference exceeds the `ms-DS-LogonTimeSyncInterval` (default 14 days). So an account that logged on 10 days ago might still show null. Use `LastLogon` (non-replicated, per-DC) and check across all DCs for higher accuracy:
```powershell
$dcs = (Get-ADDomainController -Filter *).HostName
$user = 'someuser'
$dcs | ForEach-Object {
    Get-ADUser $user -Server $_ -Properties LastLogon |
        Select-Object @{N='DC';E={$_}}, @{N='LastLogon';E={[datetime]::FromFileTime($_.LastLogon)}}
}
```

## What to audit before remediation

- **Disabled-not-deleted is fine** for a defined retention window (HR/legal often want 90 days). After that, delete.
- **Service accounts with old passwords**: confirm with the app owner what the account does before rotating. If the app is no longer in use, disable then delete.
- **Computer accounts**: a computer account in AD without a corresponding live host = clean up. But verify before deletion — some lab/test machines come and go.
- **Cross-reference with HR feed**: compare AD user list against active-employee list from HR. The delta is your candidate list.

For everything you're considering disabling/deleting:
1. **Disable first**, leave for a defined waiting period (30 days).
2. Watch for tickets, complaints, application failures.
3. Then **delete**.

## Remediation

**Bulk disable stale users (90+ days inactive):**
```powershell
$cutoff = (Get-Date).AddDays(-90)
$stale = Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -lt $cutoff }

# Move to a "Disabled Users" OU and disable
$stale | ForEach-Object {
    Set-ADUser -Identity $_ -Enabled $false -Description "Disabled $(Get-Date -Format yyyy-MM-dd) - inactive 90+ days"
    Move-ADObject -Identity $_.DistinguishedName -TargetPath "OU=DisabledUsers,$((Get-ADDomain).DistinguishedName)"
}
```

**Bulk disable stale computers:**
```powershell
$cutoff = (Get-Date).AddDays(-90)
Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonDate |
    Where-Object { $_.LastLogonDate -lt $cutoff } |
    Set-ADComputer -Enabled $false
```

**Clear PasswordNotRequired:**
```powershell
Get-ADUser -Filter { PasswordNotRequired -eq $true } | Set-ADAccountControl -PasswordNotRequired $false
```

**Clear AllowReversiblePasswordEncryption** (and force a password change for any affected user):
```powershell
Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true } | ForEach-Object {
    Set-ADUser -Identity $_ -AllowReversiblePasswordEncryption $false
    # Then force user to change password at next logon
    Set-ADUser -Identity $_ -ChangePasswordAtLogon $true
}
```

**Review PasswordNeverExpires:**
For each, ask: is this a service account that genuinely can't be rotated, or is it a human account someone set this on out of convenience? Human accounts: clear the flag, set a long but rotating password. Service accounts: migrate to gMSA where possible (auto-rotates), or document the exception with rotation responsibility assigned.

**Set up a recurring process:** monthly review of new stale accounts. The cleanup is only valuable if it stays clean.

## What might break

- A "stale" account that's actually a forgotten-but-running service account — symptom: app stops authenticating. Re-enable, investigate, document properly.
- A computer account for a host that comes online infrequently (lab gear, DR systems) — gets disabled, then doesn't work when next powered on. Easy: re-enable. Better: tag those hosts with a "do not auto-disable" marker or move them to an OU excluded from cleanup.

## Rollback

```powershell
Set-ADUser -Identity 'someuser' -Enabled $true
# Or for a deleted object, restore from AD Recycle Bin if enabled (which it should be):
Get-ADObject -Filter { Name -eq 'someuser' } -IncludeDeletedObjects | Restore-ADObject
```

## Validate the fix

Re-run the queries — counts of stale accounts should drop. Schedule the cleanup queries to run monthly and produce a report.

For ongoing assurance, **PingCastle** scores password and account hygiene as part of its overall report and is the easiest way to track improvement over time.

## References

- Microsoft: [Active Directory Recycle Bin](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/adac/introduction-to-active-directory-administrative-center-enhancements--level-100-#bkmk_recyclebin)
- Microsoft: [LastLogon vs LastLogonTimestamp](https://learn.microsoft.com/en-us/previous-versions/technet-magazine/cc875808(v=msdn.10))
- MITRE ATT&CK: T1078, T1136
