# Dangerous Built-in Groups Over-Populated

**Category:** Privileged Access
**Operational Risk of Remediation:** Low (most members are accidental)
**Attacker Skill Required to Exploit:** Low (each group has a documented escalation path)

## What it is

Several built-in AD groups confer privileges that are functionally equivalent to Domain Admin but are often forgotten in privilege reviews because their names don't sound dangerous. Membership in these groups should be tightly controlled and audited.

## What attack it enables — the rogues' gallery

- **DnsAdmins** — historically allowed loading an arbitrary DLL into the DNS service, which runs as SYSTEM on a Domain Controller. Microsoft mitigated this in 2021 (DLL must be on the local DC), but the group is still privileged. If you have local file write access to a DC, the path remains. **Treat as tier 0.**

- **Backup Operators** — can back up any file on any DC, including `NTDS.dit` (the AD database) and the SYSTEM registry hive (the boot key). Both together = offline DC compromise, all hashes including krbtgt. **Tier 0.**

- **Server Operators** — can stop/start services on DCs and modify service binaries. Replace a service binary, restart it as SYSTEM. **Tier 0.**

- **Account Operators** — can create/delete/modify most user, group, and computer accounts (excluding members of admin groups). Can effectively grant themselves rights or set up persistence. **Tier 0 in practice.**

- **Print Operators** — can manage printer drivers on DCs. Driver loading runs as SYSTEM. Pre-PrintNightmare this was a bigger deal but still relevant. **Tier 0.**

- **Schema Admins** — can modify the AD schema. Empty by default; should stay that way except during planned schema updates. **Tier 0.**

- **Group Policy Creator Owners** — can create new GPOs. Members can then link those GPOs and push code via GPO to anywhere they're applied. **High privilege.**

- **Cert Publishers** — can publish certificates to the AD forest. Combined with ADCS misconfigurations can lead to escalation. **High privilege.**

- **Remote Desktop Users** (on a DC) — anyone in this group on a DC can RDP in and attempt local privilege escalation. **Should be empty on DCs.**

MITRE ATT&CK: T1078.002

## How to confirm it's present in your environment

```powershell
$dangerousGroups = @(
    'DnsAdmins','Backup Operators','Server Operators','Account Operators',
    'Print Operators','Schema Admins','Group Policy Creator Owners',
    'Cert Publishers','Pre-Windows 2000 Compatible Access'
)

foreach ($g in $dangerousGroups) {
    $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue
    if ($members) {
        Write-Host "`n=== $g ===" -ForegroundColor Yellow
        $members | Select-Object SamAccountName, objectClass | Format-Table -AutoSize
    }
}
```

For Remote Desktop Users on each DC:
```powershell
Get-ADComputer -Filter * -SearchBase "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)" |
    ForEach-Object {
        Invoke-Command -ComputerName $_.Name -ScriptBlock {
            Get-LocalGroupMember -Group 'Remote Desktop Users'
        } -ErrorAction SilentlyContinue
    }
```

## What to audit before remediation

For each unexpected member:
- **Why are they there?** Membership often comes from a long-ago "they need to back up the DC" or "they need to manage printers" request, where the requester used the closest-named group rather than delegating specific rights.
- **What do they actually need to do?** Almost always there's a way to delegate the specific right via an OU-scoped permission instead of a domain-wide group.
- **Are any service accounts in there?** Service accounts in tier 0 groups are a classic finding. Move them to gMSAs with explicit, scoped permissions.

## Remediation

For each group, remove members that don't belong:
```powershell
Remove-ADGroupMember -Identity 'Backup Operators' -Members 'olduser','contractor' -Confirm:$false
```

**Common replacement patterns:**

- Backup Operators on DCs → use a dedicated backup service account with rights only on the backup target, or use system-state backup via the backup vendor's scoped permissions.
- DnsAdmins → for actual DNS administration delegate via the DNS Manager console with scoped zone permissions, not group membership.
- Server Operators / Print Operators → empty unless someone has a documented reason. Use specific user-rights-assignment GPOs for the narrow capability needed.
- Account Operators → use OU-scoped delegation via "Delegate Control" wizard for the specific user-management rights needed.
- Group Policy Creator Owners → only GPO admins.
- Schema Admins → empty unless mid-upgrade.
- Remote Desktop Users on DCs → empty.

## What might break

- A backup job that's been working "because the service account is in Backup Operators" — replace with explicit rights on the backup target before removing.
- A monitoring tool that uses Server Operators rights to restart services — give it scoped permissions on just those services.
- A DNS automation script that relied on DnsAdmins membership — give the script account specific zone permissions.

## Rollback

```powershell
Add-ADGroupMember -Identity 'GroupName' -Members 'user'
```
Effective on the user's next logon.

## Validate the fix

Re-run the enumeration script. Each tier-0 group should be empty or contain only documented, justified members. Re-run BloodHound — paths through these groups should be eliminated.

## References

- Sean Metcalf: [AD Built-in Groups Listing](https://adsecurity.org/?p=3658)
- Microsoft: [Active Directory security groups reference](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- shenetworks / SpecterOps writeups on DnsAdmins, Backup Operators escalation
- MITRE ATT&CK: T1078.002
