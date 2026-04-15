# LDAP Signing and Channel Binding Not Enforced

**Category:** Network Services
**Operational Risk of Remediation:** Medium-High
**Attacker Skill Required to Exploit:** Low (ntlmrelayx automates it)

## What it is

By default, Windows Domain Controllers accept LDAP binds without signing and accept LDAPS binds without channel binding. This means an attacker who captures or coerces NTLM authentication can relay it to the DC over LDAP/LDAPS and execute privileged AD actions as the victim.

This is the linchpin of NTLM relay attacks against Active Directory. Combined with LLMNR poisoning, IPv6/mitm6, WPAD, PetitPotam, or PrinterBug, an attacker can pivot from "I'm on the network" to "I have a Domain Admin shell" in minutes.

## What attack it enables

- Relay a captured Domain Admin or DC machine account NTLM auth to LDAP, then add objects, modify ACLs, write RBCD on machine accounts, or grant DCSync rights. Full domain compromise.
- Relay to LDAPS to perform privileged write operations even when LDAP signing is enforced (channel binding closes this).

MITRE ATT&CK: T1557.001, T1187

## How to confirm it's present in your environment

```powershell
# On a DC. Default value = 1 (None) means signing is requested but not required.
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -ErrorAction SilentlyContinue
# 1 = None (vulnerable), 2 = Required (good)

# Channel binding for LDAPS. Default = 0 (never) = vulnerable.
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -ErrorAction SilentlyContinue
# 0 = Never (vulnerable), 1 = When supported (good), 2 = Always (best)
```

External validation:
```bash
nmap --script ldap-rootdse -p 389 <DC-IP>
# If this returns the rootDSE without authentication and you can also bind without signing, signing is not enforced.
```

## What to audit before remediation

This is the section that determines whether you have a smooth Tuesday or a chaotic one. The clients most likely to break: older Linux servers binding via SSSD without `ldap_sasl_mech = GSSAPI`, MFPs/copiers, vendor appliances doing simple bind, legacy LOB apps, and Java apps using JNDI defaults.

**Step 1: Enable diagnostic logging on every DC.**
```powershell
# Sets "16 LDAP Interface Events" to Verbose (level 2)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
```

**Step 2: Watch the Directory Service event log for these IDs:**
- **Event ID 2887** - Aggregate count, every 24h, of unsigned/cleartext binds. Tells you scope.
- **Event ID 2889** - One per individual bind without signing. Includes client IP and bind DN. **This is your offender list.**
- **Event ID 3039** - Channel binding tokens not provided (for LDAPS).

PowerShell to collect 2889s:
```powershell
Get-WinEvent -LogName 'Directory Service' -FilterXPath "*[System[EventID=2889]]" -MaxEvents 1000 |
    Select-Object TimeCreated, @{N='ClientIP';E={$_.Properties[0].Value}}, @{N='BindDN';E={$_.Properties[1].Value}} |
    Group-Object ClientIP, BindDN | Sort-Object Count -Descending
```

**Step 3: Run for at least 1–2 weeks** to capture monthly batch jobs, quarterly reports, etc.

**Step 4: Remediate offenders one by one** either reconfigure them to use LDAPS or to bind with signing (SASL with sign-and-seal).

## Remediation

Once your 2889 events are at zero (or down to known/accepted devices on isolated VLANs):

GPO on the Domain Controllers OU:

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
- `Domain controller: LDAP server signing requirements = Require signing`
- `Domain controller: LDAP server channel binding token requirements = Always`

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
- `Network security: LDAP client signing requirements = Require signing`

Apply to one DC first. Wait 24 hours. Apply to the rest in pairs.

## What might break

- Any client that simple-binds over 389 without signing will fail. Symptom: app stops being able to read/write AD, login forms hang.
- Some older NAS/SAN appliances that authenticate users against AD.
- Some Linux servers with old SSSD/PAM configs.
- Any monitoring tool that does anonymous LDAP queries for inventory.

If you skipped the audit window, expect a help-desk surge.

## Rollback

Set both GPO settings back to "None" (signing) and "Never" (channel binding), then `gpupdate /force` on DCs. Bind failures resolve immediately.

## Validate the fix

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' |
    Select-Object LDAPServerIntegrity, LdapEnforceChannelBinding
# Want: 2 and 1 (or 2)
```

Attempt an unsigned bind from a test host:
```bash
ldapsearch -x -H ldap://dc01.example.local -D "user@example.local" -w 'Password' -b "DC=example,DC=local" "(samaccountname=user)"
# Should fail with strongAuthRequired
```

Then confirm signed bind still works:
```bash
ldapsearch -Y GSSAPI -H ldap://dc01.example.local -b "DC=example,DC=local" "(samaccountname=user)"
```

## References

- Microsoft: [ADV190023 — LDAP channel binding and LDAP signing](https://msrc.microsoft.com/update-guide/vulnerability/ADV190023)
- Microsoft: [How to enable LDAP signing in Windows Server](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)
- MITRE ATT&CK: T1557.001
