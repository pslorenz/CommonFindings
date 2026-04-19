# Entra Connect Server Treated as Member Server (Should Be Tier 0)

**Category:** Privileged Access
**Operational Risk of Remediation:** Low (it's mostly about access control)
**Attacker Skill Required to Exploit:** Low if it's already breached; getting in is the harder part — but it's a frequent target

## What it is

The server running **Microsoft Entra Connect** (previously Azure AD Connect) synchronizes on-prem AD identities to Entra ID / Microsoft 365. To do its job, it has:

- A service account in on-prem AD with **DCSync rights** on the domain (it can pull every password hash).
- A high-privilege application credential to write into Entra ID.
- If Password Hash Sync is enabled, every on-prem hash flows through this server.
- If Pass-Through Authentication is configured, every cloud auth flows through this server.

Compromise of the Entra Connect server is functionally equivalent to a Domain Admin compromise on-prem **and** Global Admin in the cloud tenant. Yet it is frequently sitting in a regular member server OU, managed by tier-1 server admins, with normal RDP access from the helpdesk.

## What attack it enables

- DCSync of the entire domain (every password hash including krbtgt → Golden Tickets).
- Manipulation of Entra ID directory (create users, assign Global Admin).
- Password spray of synced accounts.
- This is one of the highest-impact targets in any hybrid environment and is regularly named in incident-response writeups.

MITRE ATT&CK: T1003.006, T1078.004

## How to confirm it's misclassified

1. **Identify the Entra Connect server(s):**
   ```powershell
   # Look for the AD DS Connector account, typically MSOL_xxxxxxxx
   Get-ADUser -Filter { SamAccountName -like 'MSOL_*' } -Properties Description, ServicePrincipalName |
       Select-Object SamAccountName, Description
   # The Description usually identifies the server hosting Entra Connect.
   ```

2. **Check what OU the server lives in.** If it's in a generic "Servers" or "Member Servers" OU and not a dedicated tier 0 / Entra Connect OU, it is misclassified.

3. **Check who can RDP / log into it.** If the local Administrators group includes broad helpdesk or server-admin groups, it is misclassified.

4. **Check whether it's reachable from non-tier-0 networks.** It should be on a restricted management network.

## What to audit before remediation

The fix is reorganization, not turning anything off. Audit:

- Who currently administers the Entra Connect server? They will lose direct access unless they're tier 0.
- What monitoring / backup agents run on it? Confirm those agents themselves are tier 0 (a tier 0 host with a tier 1 backup agent is no longer tier 0).
- Are there any local accounts on the box? They should not exist — only domain tier 0 admins should authenticate to it.

## Remediation

Treat the Entra Connect server like a Domain Controller:

**1. Move the computer object to a dedicated tier 0 OU** with restrictive GPO inheritance. Apply the same policies as DCs (deny logon for non-tier-0 accounts, see [`domain-admins-on-workstations.md`](domain-admins-on-workstations.md)).

**2. Remove non-tier-0 principals from the local Administrators group** on the server itself.

**3. Restrict network access:**
- Inbound RDP only from PAWs.
- Outbound only to Microsoft endpoints and Domain Controllers.
- Block lateral SMB/WinRM/RDP from regular workstation subnets via host firewall.

**4. Enable LSA Protection (RunAsPPL):**
```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -PropertyType DWord
# Reboot
```

**5. Apply Credential Guard** if the host is hardware-capable.

**6. Add the Entra Connect service accounts to Protected Users** if the configuration supports it (test in a lab — some sync configurations may not).

**7. Require MFA for the Global Admin account used by Entra Connect** in the cloud — and use a dedicated, named admin account for the role, not a shared one.

**8. Enable monitoring:**
- Stream the server's security log to a SIEM.
- Alert on any logon to the host.
- Alert on any modification to the AD Connector account in on-prem AD.
- Microsoft Defender for Identity (MDI) detects classic DCSync — install the MDI sensor on DCs and review alerts.

**9. Patch promptly.** Entra Connect itself receives security updates regularly. Subscribe to Microsoft's security update notifications for this product specifically.

## What might break

- Tier 1 admins lose RDP to the server. Replace their access with documented, audited, request-based access from a PAW.
- Backup/monitoring agents may need re-installation as tier-0-managed.
- Host firewall changes need testing — confirm sync still completes after lockdown.

## Rollback

Re-add removed principals to local Administrators, move the OU back, revert firewall rules. Sync continues uninterrupted.

## Validate the fix

```powershell
# From a tier-1 admin account (not tier 0), attempt to RDP — should be denied.
# From a tier-0 admin from a PAW — should succeed.

# Check OU placement
Get-ADComputer <connect-server> -Properties DistinguishedName | Select-Object DistinguishedName

# Check local admins
Invoke-Command -ComputerName <connect-server> -ScriptBlock { Get-LocalGroupMember -Group Administrators }
```

## References

- Microsoft: [Securing Microsoft Entra Connect](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)
- Sean Metcalf: [Securing Azure AD Connect (legacy name, still applicable)](https://adsecurity.org/?p=4119)
- Microsoft: [Protecting Microsoft 365 from on-premises attacks](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks)
- MITRE ATT&CK: T1003.006, T1078.004
