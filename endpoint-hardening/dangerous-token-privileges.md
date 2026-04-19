# Dangerous Token Privileges on Service Accounts

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Medium (requires per-service review)
**Attacker Skill Required to Exploit:** Low (potato tools are one-click)

## What it is

Windows assigns token privileges to service accounts that determine what security-sensitive operations they can perform. Two privileges in particular enable instant escalation from service account to SYSTEM:

- **`SeImpersonatePrivilege`** - allows the process to impersonate any token it receives. Held by IIS application pools, SQL Server, Windows services running as Network Service or Local Service, and any account with "Impersonate a client after authentication."
- **`SeAssignPrimaryTokenPrivilege`** - allows the process to assign a primary token to a child process. Similar risk.

The "potato" family of attacks (JuicyPotato, SweetPotato, PrintSpoofer, GodPotato, RoguePotato, etc.) exploit these privileges to escalate from a service account to `NT AUTHORITY\SYSTEM` in seconds. The attack tricks a SYSTEM-level COM server or named pipe into authenticating to the attacker's process, which then impersonates the SYSTEM token.

## What attack it enables

- Web shell on IIS → JuicyPotato → SYSTEM → dump LSASS → domain compromise.
- SQL injection → xp_cmdshell → PrintSpoofer → SYSTEM.
- Any compromised service account with `SeImpersonatePrivilege` → SYSTEM.

MITRE ATT&CK: T1134.001

## How to confirm it's present

```powershell
# On a single host, list accounts with dangerous privileges
whoami /priv
# Look for SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege

# For service accounts specifically — check what each service runs as
Get-CimInstance Win32_Service | Where-Object { $_.StartName -ne 'LocalSystem' -and $_.StartName -ne $null } |
    Select-Object Name, StartName, State

# For IIS app pools
Import-Module WebAdministration
Get-ChildItem IIS:\AppPools | Select-Object Name, @{N='Identity';E={$_.processModel.identityType}}, @{N='User';E={$_.processModel.userName}}
```

The concern isn't that these privileges exist (they're needed for the services to function), it's that the service is exposed to attacker input (IIS, SQL, etc.) while running with these privileges.

## What to audit before remediation

This finding is less about removing the privilege (which would break the service) and more about reducing exposure:

1. **Which services have these privileges AND are exposed to user/network input?** Those are the attack targets. IIS, SQL Server, SSRS, custom web apps, print spooler, any internet-facing service.
2. **Are these services running as domain accounts?** A domain service account with `SeImpersonatePrivilege` that gets SYSTEM-elevated can then use its domain credentials for lateral movement. This is worse than a local-only service account.
3. **Can the service use a less-privileged identity?** IIS app pools can use `ApplicationPoolIdentity` (a virtual account with minimal privileges) instead of a domain account. SQL Server can use a gMSA.

## Remediation

You cannot simply remove `SeImpersonatePrivilege` from services that need it, they'll break. Instead, reduce the blast radius:

**1. Use virtual accounts or gMSAs instead of domain service accounts:**

IIS:
```powershell
# Set app pool to use ApplicationPoolIdentity (virtual account)
Import-Module WebAdministration
Set-ItemProperty IIS:\AppPools\<PoolName> -Name processModel.identityType -Value 'ApplicationPoolIdentity'
```

SQL Server: during install, specify a gMSA. For existing installs, use SQL Server Configuration Manager to change the service account to a gMSA.

Windows Services:
```powershell
# Create a gMSA for the service
New-ADServiceAccount -Name svc-myapp -DNSHostName myapp.example.local -PrincipalsAllowedToRetrieveManagedPassword 'CN=AppServers,OU=Groups,DC=example,DC=local'
```

**2. Remove unnecessary privileges via GPO:**

`Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment`
- `Impersonate a client after authentication` — restrict to only the accounts that genuinely need it. Remove broad groups. Default members: Administrators, SERVICE, LOCAL SERVICE, NETWORK SERVICE.
- `Replace a process level token` — same approach.

**3. Harden the service itself:**
- IIS: disable unneeded handlers (WebDAV, CGI), enable request filtering, run on the minimum AppPool identity.
- SQL Server: disable `xp_cmdshell`, restrict `EXECUTE AS` permissions, disable CLR if not used.
- Remove the Print Spooler from servers that don't print (see [`print-spooler-on-dc.md`](../legacy/print-spooler-on-dc.md)).

**4. On Server 2019+ / Windows 11+, use the mitigation for potato attacks** by disabling the DCOM call interception. Microsoft has progressively hardened DCOM activation — keep servers patched to get the latest potato mitigations.

**5. Monitor for potato attack indicators:**
- Sysmon Event ID 1: process with parent `w3wp.exe`, `sqlservr.exe`, or a service process spawning `cmd.exe`, `powershell.exe`, or a known potato binary.
- Event ID 4688 with command lines containing `GodPotato`, `PrintSpoofer`, `JuicyPotato`, or pipes like `\\.\pipe\spoolss`.

## What might break

- Removing `SeImpersonatePrivilege` from a service that needs it causes the service to fail when it tries to act on behalf of a user (e.g., IIS returning 500 errors for authenticated requests).
- Changing a service from a domain account to a virtual account may require reconfiguring file permissions, SQL logins, or network share access for the new identity.
- gMSA migration requires DNS registration and AD group configuration.

## Rollback

Re-add the privilege in the User Rights Assignment GPO, or change the service identity back to the original account.

## Validate the fix

```powershell
# On a host running IIS, check the app pool identity
Import-Module WebAdministration
Get-ChildItem IIS:\AppPools | Select-Object Name, @{N='Identity';E={$_.processModel.identityType}}
# Should show ApplicationPoolIdentity, not a domain account

# Check service accounts for unnecessary privileges
whoami /priv
# SeImpersonatePrivilege should only appear for accounts that genuinely need it
```

After hardening, attempt a potato attack from the service context in a lab. It should fail because the virtual account lacks the network identity to pivot, and DCOM mitigations on patched systems close the SYSTEM impersonation path.

## References

- Microsoft: [Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)
- Microsoft: [gMSA overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- itm4n: [PrintSpoofer](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- MITRE ATT&CK: T1134.001
