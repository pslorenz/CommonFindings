# Kerberoasting

**Category:** Kerberos
**Operational Risk of Remediation:** Low (per-account work)
**Attacker Skill Required to Exploit:** Low (Rubeus / GetUserSPNs.py)

## What it is

Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has a Service Principal Name (SPN). The TGS is encrypted with the service account's password hash (RC4 by default for legacy compatibility, AES if configured). The attacker takes the TGS offline and brute-forces the password.

This means: every service account in your domain with an SPN is a potential password-cracking target, and the attacker doesn't need to interact with the service or the account at all — just any domain user credential.

## What attack it enables

- Offline cracking of service account passwords. Service accounts are notoriously old, weak, and over-privileged.
- Once cracked, the attacker logs in as the service account — which is often a member of Domain Admins or similar.

MITRE ATT&CK: T1558.003

## How to confirm it's present in your environment

Find every account with an SPN that's a regular user (not a computer account):

```powershell
Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $true } -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
    Select-Object SamAccountName, PasswordLastSet, ServicePrincipalName, @{N='Groups';E={($_.MemberOf -join '; ')}}
```

For each account in the output, check:
1. Password age (anything over a year is suspect)
2. Group membership (any privileged groups?)
3. Whether the password complexity is actually strong (you can't see the password, but you know your policy minimum)

Simulate the attack as a defender:
```powershell
# From any domain-joined host, as any domain user
# Using the built-in Active Directory module or Rubeus
Add-Type -AssemblyName System.IdentityModel
$spns = (Get-ADUser -Filter { ServicePrincipalName -ne "$null" } -Properties ServicePrincipalName).ServicePrincipalName
foreach ($spn in $spns) {
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
}
# Tickets are now in your local cache. klist to view.
```

If this completes without error, you are exploitable. (You always are, unless you've remediated — this just proves it.)

## What to audit before remediation

The remediation is per-account, so the audit is per-account too:

1. Enumerate every SPN-holding user account (above).
2. For each, identify the actual service it runs (look at the SPN string and ask the app owner).
3. Determine whether the SPN is still needed — many are stale, attached to accounts that no longer host the service.
4. Identify password length/complexity for each account. Service accounts created before your current password policy may not meet today's requirements.

## Remediation

Apply these in priority order — high-privilege service accounts first.

**1. Use long, random passwords.** Service accounts should have ≥25 character passwords. They never type them, so length is free. Generate with:
```powershell
Add-Type -AssemblyName System.Web
[System.Web.Security.Membership]::GeneratePassword(32, 6)
```
Rotate the password and update the service to use the new one.

**2. Migrate to Group Managed Service Accounts (gMSA) wherever possible.** gMSAs have automatic 240-byte random passwords rotated every 30 days. Kerberoast-resistant in practice.
```powershell
# Create a gMSA
New-ADServiceAccount -Name svc-gMSA-app1 -DNSHostName app1.example.local -PrincipalsAllowedToRetrieveManagedPassword 'CN=AppServers,OU=Groups,DC=example,DC=local'
# Install on the target server
Install-ADServiceAccount svc-gMSA-app1
```
Then configure the service (IIS app pool, Windows Service, scheduled task) to run as `DOMAIN\svc-gMSA-app1$`.

**3. Disable RC4 for Kerberos** so even if a password is weak-ish, only AES tickets are issued and AES is far slower to crack:
- GPO: `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos = AES128, AES256, Future encryption types`
- **Audit first**: Some legacy apps and trust relationships still negotiate RC4. Check Event ID 4769 on DCs for ticket encryption type. See [`ntlmv1-enabled.md`](../authentication-protocols/ntlmv1-enabled.md) for similar audit pattern.

**4. Remove unnecessary SPNs** from accounts that don't actually host the service anymore.
```powershell
Set-ADUser -Identity stale-svc-account -Clear ServicePrincipalName
```

**5. Get service accounts out of privileged groups.** A kerberoasted account that's a regular user is annoying. A kerberoasted Domain Admin is game over.

## What might break

- Rotating a service account password without updating the service config will break the service. Always coordinate with the app owner.
- gMSA migration: the service must support running under a gMSA. Most modern Microsoft services do. Some older third-party software does not — check vendor docs.
- Disabling RC4: see audit warning above. Some app-server-to-DC tickets and some inter-forest trusts may still use RC4.

## Rollback

Per-account: keep the old password until the new one is confirmed working.
RC4 GPO: revert to "RC4, AES128, AES256" (the default) and `gpupdate /force`.

## Validate the fix

After remediation, re-run the `New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken` loop and request tickets. Then in attacker terms (lab only), try to crack with hashcat mode 13100. If passwords are 25+ characters and random, the cracker will exhaust without a hit.

```powershell
# Confirm tickets are AES, not RC4
klist
# Look at "KerbTicket Encryption Type" — should say AES-256-CTS-HMAC-SHA1-96
```

## References

- Sean Metcalf: [Detecting Kerberoasting Activity](https://adsecurity.org/?p=3458)
- Microsoft: [Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- MITRE ATT&CK: T1558.003
