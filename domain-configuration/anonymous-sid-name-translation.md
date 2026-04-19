# Anonymous SID/Name Translation Enabled

**Category:** Domain Configuration
**Operational Risk of Remediation:** Very Low
**Attacker Skill Required to Exploit:** Trivial

## What it is

Two related legacy Windows behaviors:
- **Anonymous SID-to-name translation** (`LSAAnonymousNameLookup`) lets unauthenticated callers look up an account name from a SID and vice versa via the LSA RPC interface.
- **Allow anonymous SAM enumeration** (`RestrictAnonymousSAM` / `RestrictAnonymous`) lets unauthenticated callers list user and group accounts.

Together, they let an attacker on the network — with no credentials at all — enumerate domain users, groups, the Domain Admins membership, and the privileged-account hit list before they have a single foothold.

## What attack it enables

Pre-authentication reconnaissance. Specifically:
- Enumerate Domain Admins membership.
- Identify high-value targets for password spraying or phishing.
- Build the user list for AS-REP roasting attempts (no auth needed).

## How to confirm it's present

```powershell
# On a DC
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsa | Select-Object RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous
# Goal: RestrictAnonymousSAM = 1, RestrictAnonymous = 1, EveryoneIncludesAnonymous = 0

Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LSAAnonymousNameLookup -ErrorAction SilentlyContinue
# Should be 0 or absent
```

External test:
```bash
# From any host that can reach the DC, no creds:
rpcclient -U "" -N <dc-ip>
rpcclient $> enumdomusers
# If this returns user accounts, anonymous enumeration is allowed.

# Or with impacket:
lookupsid.py 'anonymous@<dc-ip>'
```

## What to audit before remediation

These settings have been hardened by default since Server 2003, so most environments are already fine. The risk case is upgrades from very old domains where the legacy permissive value carried forward, or environments where someone enabled "Pre-Windows 2000 Compatible Access" (see [`pre-win2k-compatible-access.md`](pre-win2k-compatible-access.md)) and never undid it.

If the test command above returns user accounts, you have the problem.

## Remediation

GPO on Default Domain Controllers Policy:

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`:
- `Network access: Allow anonymous SID/Name translation = Disabled`
- `Network access: Do not allow anonymous enumeration of SAM accounts = Enabled`
- `Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled`
- `Network access: Let Everyone permissions apply to anonymous users = Disabled`

Also remove the `Pre-Windows 2000 Compatible Access` group's membership of `Anonymous Logon` if present (see linked finding).

## What might break

Almost nothing in modern environments. Specific risk areas:
- Some very old NT4 trust scenarios (which should not exist in 2026).
- Some legacy Samba clients in workgroup mode.
- A handful of specialty appliances (very old SAN/NAS) that anonymously query SIDs.

## Rollback

Reverse the GPO settings and `gpupdate /force` on DCs.

## Validate

Re-run the `rpcclient` test — should now return access denied.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' | Select-Object RestrictAnonymous, RestrictAnonymousSAM, EveryoneIncludesAnonymous
# 1, 1, 0
```

## References

- Microsoft: [Network access: Do not allow anonymous enumeration of SAM accounts](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts)
- MITRE ATT&CK: T1087.002
