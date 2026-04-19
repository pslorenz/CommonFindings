# RDP Credential Exposure (No Restricted Admin / Remote Credential Guard)

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Low-Medium
**Attacker Skill Required to Exploit:** Low (mimikatz on the RDP target)

## What it is

When an administrator RDPs to a remote server using standard RDP, the administrator's credentials are sent to and cached in LSASS on the target host. If the target is compromised, the attacker extracts those credentials and impersonates the admin anywhere in the domain.

This is the specific mechanism behind "a Domain Admin logged into a workstation and we got their password" and it applies to every admin who RDPs to servers they don't fully trust.

Two mitigations exist:

- **Restricted Admin Mode** (Server 2012 R2+): the admin's credentials are never sent to the target. Instead, the RDP session authenticates to the target using the target's machine account. The admin gets a local SYSTEM-equivalent shell on the target but has no network identity from that session (single-hop only, no pass-through to other servers).
- **Remote Credential Guard** (Server 2016+ / Win10 1607+): the admin's credentials stay on the source machine and are forwarded via Kerberos. The admin gets full network SSO from the remote session without credentials ever touching the target's LSASS. This is the preferred option.

## What attack it enables (without the fix)

- Credential theft from any server the admin RDPs to.
- "Credential hopping" - admin RDPs to Server A → attacker on Server A steals creds → attacker pivots to anything that admin can access.

MITRE ATT&CK: T1021.001, T1003.001

## How to confirm the gap exists

Check whether Remote Credential Guard or Restricted Admin is enforced:

```powershell
# Remote Credential Guard
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowProtectedCreds -ErrorAction SilentlyContinue
# Absent or 0 = not configured

# Restricted Admin mode allowed (server-side must also allow)
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -ErrorAction SilentlyContinue
# 1 = restricted admin disabled (default on some versions), 0 = enabled
```

Practical test: RDP to a server normally, then on the server run `klist`, if you see a TGT for the admin user, credentials were sent to the server.

## What to audit before remediation

**Remote Credential Guard considerations:**
- Requires Kerberos authentication, so the RDP client must connect using the hostname (not IP address).
- Does not work for RDP to non-domain-joined hosts, workgroup machines, or hosts in untrusted domains.
- The admin cannot use their network identity from the remote host to connect to *third* hosts that require explicit delegation (it uses Kerberos forwarding, but some apps may not support it).
- Second-hop scenarios: if the admin needs to open a file share or connect to SQL Server from within the RDP session, Remote Credential Guard handles this via Kerberos. Most scenarios work; test application-specific ones.

**Restricted Admin Mode considerations:**
- No network identity from the remote session. Any attempt to access a network resource from the RDP session authenticates as the target host's machine account, not the admin. This breaks network file shares, SQL connections, and other double-hop scenarios from within the RDP session.
- **Security caution**: Restricted Admin Mode makes the admin's NT hash usable for pass-the-hash to that host (because the remote host accepts the hash without credentials). If an attacker has the admin's hash, they can RDP with Restricted Admin. This is a known tradeoff.

**Recommendation**: Remote Credential Guard for admin workstations → servers. Restricted Admin only where Remote Credential Guard isn't available.

## Remediation

### Remote Credential Guard (preferred)

**On the target servers (allow the feature):**

GPO or registry:
```powershell
# Not strictly required on the server side for Remote Credential Guard — 
# the GPO is set on the CLIENT side. But ensure the server allows NLA:
# Computer Configuration → Admin Templates → Windows Components → Remote Desktop Services → 
# Remote Desktop Session Host → Security → Require user authentication for remote connections = Enabled
```

**On the admin workstations / PAWs (enforce the feature):**

GPO:
`Computer Configuration → Policies → Administrative Templates → System → Credentials Delegation`
- `Restrict delegation of credentials to remote servers = Enabled`
- Select: **Require Remote Credential Guard**

Or registry:
```powershell
New-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name AllowProtectedCreds -Value 1 -PropertyType DWord -Force
```

**Usage (manual per-session):**
```cmd
mstsc /remoteGuard
```

### Restricted Admin Mode (fallback)

**On the target server (allow connections in Restricted Admin):**
```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DisableRestrictedAdmin -Value 0
```

**Usage:**
```cmd
mstsc /restrictedAdmin
```

## What might break

- **Remote Credential Guard**: apps that don't support Kerberos delegation from a forwarded ticket context. Most standard admin tasks (file shares, AD tools, SQL Management Studio) work fine.
- **Restricted Admin**: anything requiring network identity from the RDP session fails. The admin must connect to network resources from their local workstation instead of from inside the RDP session.
- Both modes require NLA on the target server (which it should have, see the NLA finding).
- RDP to non-domain-joined hosts: neither mode works. Use a VPN or bastion host in those scenarios.

## Rollback

Remove the GPO setting or set `AllowProtectedCreds = 0`. Standard RDP credential behavior resumes at next connection.

## Validate the fix

After connecting via Remote Credential Guard:
```powershell
# On the remote server
klist
# Should NOT show a TGT for the admin user
# Instead, ticket requests are proxied back to the source machine
```

After connecting via Restricted Admin:
```powershell
# On the remote server
whoami
# Shows the admin's username, but:
klist
# Shows only the machine account's ticket, not the admin's TGT
net use \\otherserver\share
# Fails with access denied (no network identity)
```

## References

- Microsoft: [Remote Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard)
- Microsoft: [Restricted Admin mode](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-068)
- MITRE ATT&CK: T1021.001, T1003.001
