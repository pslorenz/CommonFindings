# WinRM / PSRemoting Open to All

**Category:** Endpoint Hardening
**Operational Risk of Remediation:** Low-Medium
**Attacker Skill Required to Exploit:** Low (Enter-PSSession with stolen creds)

## What it is

Windows Remote Management (WinRM, TCP 5985/5986) is the transport for PowerShell Remoting, the modern way to manage Windows endpoints. On servers, WinRM is typically enabled by default or via GPO. On workstations, it's enabled in many environments for SCCM, Intune, or central management.

The problem isn't that WinRM exists — it's that it's usually accessible from **any source** on the network. An attacker with a valid domain credential (even a regular user) and network access to port 5985 can get a remote shell on any host where they have local admin rights. Combined with shared local admin passwords (pre-LAPS) or credential reuse, WinRM becomes the fastest lateral movement channel.

## What attack it enables

- Lateral movement via `Enter-PSSession`, `Invoke-Command`, or Evil-WinRM from any compromised host.
- Fileless execution — commands run in memory on the target with no binary dropped.
- WinRM-based C2 (some frameworks use WinRM as a transport).

MITRE ATT&CK: T1021.006

## How to confirm the current state

```powershell
# Is WinRM listening?
Get-Service WinRM | Select-Object Status, StartType
Test-NetConnection -ComputerName localhost -Port 5985

# What's the listener configuration?
winrm enumerate winrm/config/listener
# Or:
Get-WSManInstance -ResourceURI winrm/config/listener -Enumerate

# Who can connect?
Get-PSSessionConfiguration | Select-Object Name, Permission
```

From a test host, attempt to connect from a non-admin subnet:
```powershell
Test-WSMan -ComputerName <target>
# If this succeeds from any workstation, WinRM is open to all.
```

## What to audit before remediation

WinRM is used by:
- **SCCM / Intune** for remote management.
- **PowerShell DSC** for configuration management.
- **Admin tooling** - `Enter-PSSession`, `Invoke-Command` for remote troubleshooting.
- **SIEM / monitoring agents** that use WinRM for remote event log collection (Windows Event Forwarding).
- **Ansible** for Windows host management.
- **JEA (Just Enough Administration)** endpoints.

You don't want to disable WinRM — you want to restrict **who can reach it** and **what they can do**.

Identify the source subnets that need WinRM access:
- Management / jump server subnets.
- SCCM site server(s).
- Monitoring / collector server(s).
- Admin PAW subnet.

## Remediation

**1. Restrict WinRM via Windows Firewall (most effective):**

See [`windows-firewall.md`](windows-firewall.md) for the firewall setup. The specific rule:

```powershell
# Remove the default "allow from any" WinRM rule
Get-NetFirewallRule -DisplayName 'Windows Remote Management*' | Remove-NetFirewallRule

# Add a restricted rule
New-NetFirewallRule -DisplayName "WinRM - Admin Subnet Only" -Direction Inbound -Protocol TCP -LocalPort 5985 -RemoteAddress '10.0.20.0/24','10.0.30.0/24' -Action Allow -Profile Domain
```

Via GPO:
`Computer Configuration → Windows Settings → Security Settings → Windows Defender Firewall → Inbound Rules`
Create a new rule for TCP 5985 restricted to specific source subnets.

**2. Use JEA (Just Enough Administration) to limit what remote sessions can do:**

JEA creates constrained PSSession endpoints where users can only run specific pre-approved cmdlets. This way, even if an attacker connects via WinRM, they can't run arbitrary commands.

```powershell
# Example JEA session configuration
New-PSSessionConfigurationFile -Path .\helpdesk.pssc `
    -SessionType RestrictedRemoteServer `
    -VisibleCmdlets 'Get-Process','Get-Service','Restart-Service' `
    -LanguageMode NoLanguage `
    -RunAsVirtualAccount

Register-PSSessionConfiguration -Name HelpDesk -Path .\helpdesk.pssc
```

**3. Disable WinRM on hosts that don't need it** (rare since many endpoints need it for management, but kiosks, shared terminals, etc. may not):

```powershell
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled
```

**4. Enforce HTTPS for WinRM (port 5986) if credentials transit untrusted networks:**

```powershell
winrm quickconfig -transport:https
# Requires a valid certificate on the endpoint
```

## What might break

- Management tools that expect WinRM from any source IP will fail from non-allowed subnets. Add their subnets to the firewall rule.
- JEA restrictions may block admin tasks that aren't in the allowed cmdlet list. Expand the JEA role capabilities as needed.
- Disabling WinRM breaks all PowerShell Remoting, SCCM remote features, and WEF subscription collection from that host.

## Rollback

Re-add the default WinRM firewall rule:
```powershell
New-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Domain
```

## Validate the fix

From a **non-admin** subnet:
```powershell
Test-WSMan -ComputerName <target>
# Should fail / time out
```

From the **admin** subnet:
```powershell
Test-WSMan -ComputerName <target>
# Should succeed
Enter-PSSession -ComputerName <target>
# Should connect
```

## References

- Microsoft: [WinRM Security](https://learn.microsoft.com/en-us/windows/win32/winrm/winrm-security)
- Microsoft: [Just Enough Administration](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview)
- MITRE ATT&CK: T1021.006
