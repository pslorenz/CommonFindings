# Cached Domain Credentials (CachedLogonsCount)

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Low-Medium (laptop users need some cached logons)
**Attacker Skill Required to Exploit:** Low (secretsdump / mimikatz)

## What it is

Windows caches a derivative of domain credentials locally so users can log in when the Domain Controller is unreachable (e.g., a laptop off the corporate network). By default, Windows caches the **last 10 unique domain logon credentials** in the SAM database as MS-CacheV2 (DCC2) hashes.

An attacker with local admin access can extract these cached credentials using `secretsdump.py`, `mimikatz lsadump::cache`, or similar tools. DCC2 hashes are slow to crack (bcrypt-like per-iteration cost), but weak passwords still fall and the attacker only needs one.

The risk scales with the number: caching 10 credentials means 10 potential cracking targets, including any privileged account that has ever logged into the machine interactively.

## What attack it enables

- Offline cracking of cached domain credentials found on a compromised endpoint.
- Particularly dangerous when IT staff or developers log into workstations with elevated accounts — those caches persist until overwritten.

MITRE ATT&CK: T1003.005

## How to confirm the current setting

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount
# Default: 10
```

## What to audit before remediation

The core tradeoff:
- **Desktops always on the network**: can safely be set to `1` or even `0`. They always reach a DC. If the DC is down, you have bigger problems.
- **Laptops**: need at least `1` so the user can log in offline (e.g., airplane mode). `2` gives a margin for when a user changes their password and hasn't connected yet. Going above `2` is rarely justified.
- **Servers**: should always reach a DC. Set to `1` or `0`.
- **Kiosks / shared workstations**: `0` if they always have DC connectivity.

Before reducing from 10 to 1 on laptops, confirm your VPN situation. If users must log in to Windows before the VPN connects (no "always-on VPN"), they need at least 1 cached logon. If you have always-on VPN or DirectAccess / Azure AD join with cloud auth, you can go lower.

Also consider: who has logged into these endpoints? The cached credentials include whoever has done interactive or RDP logons. If a Domain Admin logged into a workstation three months ago, their DCC2 hash is still sitting there. Reducing the count doesn't clear existing caches, see "Remediation" for how to flush them.

## Remediation

**Via GPO:**
`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Interactive logon: Number of previous logons to cache (in case domain controller is not available)`

Recommended values:
- Desktops / Servers: `1`
- Laptops: `2`
- High-security environments: `0` (requires guaranteed DC connectivity)

**Via registry:**
```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name CachedLogonsCount -Value 2
# Takes effect at next logon cycle
```

**Important: flush existing stale caches.** Reducing the count doesn't immediately purge old entries as they are overwritten as new logons occur. To force a flush, each user needs to log on again until the cache cycles. Alternatively, after reducing the count, you can clear cached credentials by having each user log off and back on while connected to the DC.

For high-security environments, proactively flush caches on sensitive systems:
```powershell
# Identify what's cached (requires SYSTEM)
# mimikatz # lsadump::cache (lab only, to see how many entries exist)
```

## What might break

- Users who log in to their laptop offline with no DC connectivity will fail if the count is `0`.
- Password changes while offline: if a user changes their domain password from another device while their laptop is offline, the laptop's cache has the old password. This is normal and resolves on next DC contact, but if the cache is set to `1` and they changed passwords, the old cached credential is already the only one available (which is correct behavior, they log in with the old password, then it syncs).

## Rollback

Set the value back to `10` (or desired level) via GPO or registry. Effective at next logon.

## Validate the fix

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').CachedLogonsCount
# Should match your target
```

Test offline logon on a laptop with the new setting, should work with the most recent credential.

## References

- Microsoft: [Interactive logon: Number of previous logons to cache](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available)
- MITRE ATT&CK: T1003.005 (Cached Domain Credentials)
