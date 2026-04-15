# LLMNR / NBT-NS Poisoning

**Category:** Authentication Protocols
**Operational Risk of Remediation:** Low
**Attacker Skill Required to Exploit:** Low (Responder is point-and-click)

## What it is

Link-Local Multicast Name Resolution (LLMNR, UDP 5355) and NetBIOS Name Service (NBT-NS, UDP 137) are legacy fallback name-resolution protocols Windows uses when DNS fails. They broadcast "does anyone know the IP for `<name>`?" to the local subnet, and any host on the subnet can answer.

## What attack it enables

An attacker on the same broadcast domain runs Responder (or Inveigh) and answers every broadcast query with "yes, that's me." Victims then attempt to authenticate to the attacker's box, sending NTLMv2 hashes that can be cracked offline or relayed. This is the most common first-five-minutes win on an internal pentest.

MITRE ATT&CK: T1557.001

## How to confirm it's present in your environment

From a Windows host on a typical user subnet:

```powershell
# LLMNR — registry value 0 or absent = enabled
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue

# NBT-NS — per-interface, value 0 (default) or 1 = enabled, 2 = disabled
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
    ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object PSChildName, NetbiosOptions }
```

From a Linux box on the same subnet (passive, safe):

```bash
sudo responder -I eth0 -A
# -A is analyze mode. It listens but does NOT poison. If you see queries, you're vulnerable.
```

## What to audit before remediation

LLMNR/NBT-NS being used legitimately is rare in modern environments, but it does happen with old line-of-business apps that hardcode short names.

- Run `responder -A` for a few hours during business hours and review the captured queries. Any query that resolves to a real internal hostname when you look it up in DNS is fine to ignore (DNS will handle it). Queries for typos or names that don't exist in DNS are also fine as those would have failed anyway.
- Genuine concern: queries for short hostnames that *do* successfully resolve via NBT-NS today but have no DNS record. Those workflows will break. Add the missing DNS records first.

## Remediation

GPO scope: link to OU containing all workstations and servers (or domain root if you want everyone).

**Disable LLMNR:**
`Computer Configuration → Policies → Administrative Templates → Network → DNS Client → Turn off multicast name resolution = Enabled`

**Disable NBT-NS** (no native GPO — use one of the following):

Option A — DHCP scope option (cleanest if you control DHCP):
- DHCP Server → Scope Options → `001 Microsoft Disable Netbios Option` → value `0x2`
- Clients pick this up on next lease renewal.

Option B — startup script via GPO:
```powershell
$adapters = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
foreach ($a in $adapters) {
    Set-ItemProperty -Path $a.PSPath -Name NetbiosOptions -Value 2
}
```

## What might break

- Very old apps (think Windows 2003-era line-of-business software) that resolve unqualified short names without DNS suffixes.
- Some old network printer discovery.
- Workgroup file sharing across subnets without DNS — but in an AD environment this should not exist.

In practice, this is one of the safest hardening steps. Most environments see zero incidents.

## Rollback

Reverse the GPO setting (set "Turn off multicast name resolution" to Disabled or Not Configured) and rerun the NBT-NS script with value `0` instead of `2`. Effective on next `gpupdate /force`.

## Validate the fix

```powershell
# On a remediated client, this should show EnableMulticast = 0
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast

# And NetbiosOptions = 2 on each interface
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' |
    ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object PSChildName, NetbiosOptions }
```

Then re-run `responder -A` from a test host — there should be no LLMNR or NBT-NS queries from remediated machines.

## References

- Microsoft: [Disabling LLMNR](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-client-resolution-timeouts)
- Responder project: https://github.com/lgandx/Responder
- MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)
