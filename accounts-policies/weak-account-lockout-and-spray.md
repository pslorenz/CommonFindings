# Weak Account Lockout / Password Spray Exposure

**Category:** Accounts & Policies
**Operational Risk of Remediation:** Low-Medium (helpdesk volume changes)
**Attacker Skill Required to Exploit:** Trivial (DomainPasswordSpray.ps1, Spray365, MSOLSpray)

## What it is

Password spray is the inverse of brute force: instead of trying many passwords against one account (which trips lockout), the attacker tries one or two common passwords (e.g., `Winter2025!`, `Spring2026!`, `<CompanyName>1`) against every account in the directory. With thousands of accounts, statistically *someone* uses that password — and lockout never triggers because each account only sees one or two attempts.

The defenses are: (1) actually have a strong password policy with a banned-password list, (2) have a lockout policy that triggers on broad failure patterns, and (3) detect spray attempts in logs.

## What attack it enables

- Initial domain credential access without phishing or any malware.
- Often the first step in ransomware operator workflows that don't bother with social engineering.
- In hybrid environments, sprays often hit the cloud auth endpoint (Entra ID), bypass on-prem lockout entirely, and use the captured credential to RDP / VPN in.

MITRE ATT&CK: T1110.003

## How to confirm it's present in your environment

**Check the password policy:**
```powershell
Get-ADDefaultDomainPasswordPolicy
# Look at: MinPasswordLength, ComplexityEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow
```

**Common bad signs:**
- `MinPasswordLength` < 12
- `LockoutThreshold` = 0 (no lockout at all) or > 50
- `LockoutDuration` very short (1 minute) — attacker just waits
- `LockoutObservationWindow` short — failures roll off too fast
- `ComplexityEnabled` = $true but no banned-words list — `Password1!` meets complexity

**Test the password policy in practice** (lab/authorized testing only) — try a small spray with a deliberately wrong password against your own test account, confirm lockout actually triggers.

**Check for fine-grained password policies** that may override the default for specific groups:
```powershell
Get-ADFineGrainedPasswordPolicy -Filter *
```

**Find accounts that are exempt from password requirements:**
```powershell
# PASSWD_NOTREQD flag set
Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -Properties PasswordNotRequired |
    Select-Object SamAccountName

# Password never expires
Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordLastSet, PasswordNeverExpires |
    Select-Object SamAccountName, PasswordLastSet
```

## What to audit before remediation

- **Current helpdesk lockout volume**: get a 30-day baseline of Event ID 4740 (account locked out). If you tighten lockout thresholds, expect this to go up. Make sure helpdesk has self-service password reset (SSPR) or efficient unlock workflow first.
- **Service accounts**: confirm none of them are at risk of being locked out by spray. Service accounts should have very long passwords and be excluded from interactive login attempts.
- **Hybrid auth path**: if you're on Entra ID with synced auth, configure Smart Lockout in the cloud (it's on by default but check the threshold). Smart Lockout protects against cloud-based spray independently of on-prem lockout.

## Remediation

Modern Microsoft / NIST guidance: **length over complexity, banned-password list, no forced rotation**.

**Default Domain Policy:**
- `MinPasswordLength`: 14 minimum (NIST suggests 8+, but for a domain that includes admins, push higher).
- `ComplexityEnabled`: keep enabled (it's still a baseline filter).
- `MaxPasswordAge`: 365 days or longer if you have other compensating controls (NIST no longer recommends scheduled rotation absent compromise).
- `MinPasswordAge`: 1 day (prevents rapid cycling through history).
- `PasswordHistoryCount`: 24.

**Lockout policy** — modern guidance (CIS, MS):
- `LockoutThreshold`: 10 (low enough to stop spray, high enough to absorb legitimate fat-finger).
- `LockoutDuration`: 15 minutes (auto-unlocks; reduces helpdesk burden).
- `LockoutObservationWindow`: 15 minutes.

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) `
    -MinPasswordLength 14 `
    -LockoutThreshold 10 `
    -LockoutDuration (New-TimeSpan -Minutes 15) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 15) `
    -PasswordHistoryCount 24
```

**Banned password list** — the single highest-value addition. Options:
- **Entra Password Protection** extends the cloud's banned-password list (which includes leaked passwords) to on-prem AD via a lightweight agent. This is the modern approach and the only way to block "Winter2025!" type passwords cheaply. Requires deploying the Password Protection Proxy and DC Agent.
- Open-source lists (have-i-been-pwned, SecLists) integrated via custom PowerShell scripts — works but more maintenance overhead.

**Fix exempt accounts:**
```powershell
# Clear PasswordNotRequired
Get-ADUser -Filter { PasswordNotRequired -eq $true } | Set-ADAccountControl -PasswordNotRequired $false

# Review and remove PasswordNeverExpires for human accounts. Service accounts should rotate too — every 12 months, rotated by the team that owns them.
```

**Cloud / hybrid:**
- Entra Smart Lockout: configure in Entra portal under Security → Authentication methods → Password protection. Default lockout threshold is 10 failed attempts; tune for your environment.
- Conditional Access: require MFA, especially for any account that's a target of cloud spray.
- Disable legacy authentication (POP, IMAP, SMTP basic auth) which bypasses MFA and is the classic spray target.

## What might break

- Tighter lockout: more user lockouts during normal "I forgot my password" flow. Mitigate with SSPR.
- Longer minimum password length: users complain on next password change. Provide guidance toward passphrases.
- Banned password list: rejects current weak passwords on next change. Users will need 1-2 attempts to land on something accepted. This is the goal.

## Rollback

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) -LockoutThreshold 0 -MinPasswordLength 7
```
Effective on next replication.

## Validate the fix

```powershell
Get-ADDefaultDomainPasswordPolicy
# Confirm new values
```

Test a spray simulation against your own infrastructure (with authorization):
```powershell
# DomainPasswordSpray, with a single deliberately wrong password
Invoke-DomainPasswordSpray -Password 'WrongPassword123!' -OutFile sprayed.txt
# Should result in LOCKOUT events (Event ID 4740) on DCs, and the attempts should be detectable in your SIEM.
```

Check for **Event ID 4740** (account locked) and **Event ID 4625** (failed logon) in DC Security logs — at scale, baseline these and alert on anomalies (many 4625s for many different users in a short window = active spray).

## References

- NIST SP 800-63B (Digital Identity Guidelines, Authenticator section)
- Microsoft: [Entra Password Protection](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises)
- DomainPasswordSpray: https://github.com/dafthack/DomainPasswordSpray
- Microsoft: [Smart lockout](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)
- MITRE ATT&CK: T1110.003
