# Weak or Outdated Domain Password Policy

**Category:** Governance
**Operational Risk of Remediation:** Medium (users will need to reset)
**Attacker Skill Required to Exploit:** Low (password spraying)

## What it is

Many domains still run on the legacy default password policy: 7-character minimum, complexity enabled, 90-day expiration, lockout after 5 attempts. Modern guidance (NIST SP 800-63B, Microsoft) has moved away from short complex passwords with frequent rotation toward longer passphrases without forced rotation, combined with breach-list checking and MFA.

A weak policy enables password spraying and credential-stuffing attacks. A complex-but-rotated policy encourages predictable patterns (`Summer2026!`).

## What attack it enables

- Password spraying: try `Password1!`, `Welcome2026!`, `Spring2026!` against every user. With a 5-attempt lockout, a careful sprayer (1 attempt every 30 minutes) won't trigger lockouts.
- Offline cracking of any captured hash (Kerberoast, AS-REP roast, NTDS.dit dump) is dramatically faster against short passwords.

## How to confirm the current state

```powershell
# Default domain policy
Get-ADDefaultDomainPasswordPolicy | Format-List

# Fine-Grained Password Policies (PSOs) attached to specific groups
Get-ADFineGrainedPasswordPolicy -Filter * | Format-List Name, Precedence, MinPasswordLength, ComplexityEnabled, MaxPasswordAge, LockoutThreshold
```

Reasonable target state (combine with MFA wherever possible):
- Minimum length: **14 characters** for users, **25+** for service accounts (gMSA preferred).
- Complexity: **enabled** (mixed character classes).
- Maximum age: **never expire** (NIST guidance) **provided** you have:
  - MFA on all external-facing access, AND
  - Continuous breach-list checking (Azure AD Password Protection, Specops, Have I Been Pwned API check at change time).
- If you can't meet both of those: keep an annual rotation as compromise.
- Account lockout: **5 attempts** in **30 minutes**, lockout duration **30 minutes**.
- History: **24 passwords**.

## What to audit before changing

**Lockout threshold changes** are the easiest way to lock out the entire company. If you change the threshold from "5 in 30 min" to "3 in 1 hour" without warning, the next time someone fat-fingers their password three times they're locked out for an hour.

For length increases:
- Plan a forced reset cycle (or `pwdLastSet=0` to force change at next login).
- Communicate weeks ahead. People hate password changes.

For ditching expiration:
- Make sure you have breach-list checking in place. Otherwise you're leaving compromised passwords in use indefinitely.
- Audit current password ages — some accounts will have passwords >2 years old that you should rotate one final time.

## Remediation

Change the default domain policy via Group Policy Management Console:

`Default Domain Policy → Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy`

Or via PowerShell:
```powershell
Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain) `
    -MinPasswordLength 14 `
    -ComplexityEnabled $true `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 30) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
    -PasswordHistoryCount 24
```

For different policies on different account types, use Fine-Grained Password Policies attached to security groups (e.g., a stricter policy for admins, longer for service accounts).

For breach-list checking on-prem: Azure AD Password Protection has an on-premises agent, or use a third-party (Specops, Enzoic).

## What might break

- Users who ignored emails about the new minimum length will be unable to change passwords until they pick a long enough one.
- Some apps with hardcoded short passwords (rare, but seen with old vendor accounts).
- Any service account that can't be rotated yet.

## Rollback

Set the policy values back. Active sessions are unaffected; the new requirements apply at next password change.

## Validate

```powershell
Get-ADDefaultDomainPasswordPolicy
# Verify all values match target.
```

Audit current weak passwords by dumping hashes from a DC (in a controlled, authorized way) and running them through hashcat with a common-password wordlist:
- Use `secretsdump.py` or `ntdsutil ifm` (with appropriate authorization and chain of custody).
- Crack against rockyou + the year + your company name + common patterns.
- Force resets on any account whose password cracks.

## References

- NIST SP 800-63B: [Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- Microsoft: [Password policy recommendations](https://learn.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations)
- Microsoft: [Azure AD Password Protection](https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-on-premises)
- MITRE ATT&CK: T1110.003 (Password Spraying)
