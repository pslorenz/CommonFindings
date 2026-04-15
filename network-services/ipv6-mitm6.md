# IPv6 / mitm6 Attack

**Category:** Network Services
**Operational Risk of Remediation:** Low (if done correctly) / High (if you blindly disable IPv6)
**Attacker Skill Required to Exploit:** Low (mitm6 + ntlmrelayx are turn-key)

## What it is

Windows ships with IPv6 enabled and prefers it over IPv4 when both are available. In most enterprise networks, IPv6 is enabled on hosts but unused — there is no DHCPv6 server, no router advertisements, no IPv6 DNS. An attacker on the local subnet runs `mitm6`, which acts as a rogue DHCPv6 server, hands out the attacker's address as the DNS server, and now sees and modifies every DNS lookup the victim makes — paving the way for WPAD attacks, NTLM relay, and credential capture.

## What attack it enables

- DNS hijacking on every IPv6-enabled Windows client on the subnet.
- Combined with NTLM relay to LDAPS, can result in domain takeover within minutes.
- This is currently one of the highest-impact internal attacks because most environments have not addressed it.

## How to confirm it's present in your environment

Two things matter: (a) is IPv6 enabled on clients, and (b) does the network L2 fabric prevent rogue DHCPv6 advertisements.

```powershell
# IPv6 enabled state
Get-NetAdapterBinding -ComponentID ms_tcpip6 | Select-Object Name, Enabled
# Most environments: Enabled = True everywhere
```

To test whether the network is vulnerable, run mitm6 in observe-only fashion from a lab box on the subnet and watch a Windows client request a DHCPv6 lease. If the client accepts the assignment, the network is vulnerable.

## What to audit before remediation

**Critical**: Do NOT disable IPv6 outright as a first response. Microsoft explicitly does not recommend disabling IPv6, and it can cause:
- Slow startup times
- Issues with Exchange, DirectAccess, Failover Clustering, Hyper-V
- Hard-to-diagnose breakage that's a pain to undo at scale

Audit before remediation:
- Is IPv6 actually used anywhere internally? Most enterprises: no.
- Is IPv6 used externally (do client subnets have legitimate DHCPv6)? Most enterprises: no.
- Does any application bind to or require IPv6? Check with `Get-NetTCPConnection | Where-Object LocalAddress -match ':'`.

## Remediation

In order of preference:

**Option 1 (best) — Fix it at L2.** Configure DHCPv6 Guard and Router Advertisement (RA) Guard on all access switch ports. This drops rogue DHCPv6 and RA frames at the switch, regardless of what clients do. Cisco: `ipv6 nd raguard` and `ipv6 dhcp guard`. Most enterprise switches support this. **This breaks nothing** because legitimate DHCPv6/RA traffic only originates from designated trunk/uplink ports.

**Option 2 — Configure Windows clients to ignore rogue DHCPv6 without disabling IPv6.** Set the IPv6 prefix policy to prefer IPv4:
```powershell
# Run on each host or via GPO
Set-NetIPv6Protocol -RandomizeIdentifiers Disabled
# Plus: prefer IPv4 over IPv6
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -Value 0x20
```
The value `0x20` prefers IPv4 without disabling IPv6 entirely. **Avoid `0xFF`** (fully disable) — that's the option that breaks Microsoft services.

**Option 3 — Block DHCPv6 on the host firewall.** Less elegant but works:
```powershell
New-NetFirewallRule -DisplayName "Block DHCPv6 In" -Direction Inbound -Protocol UDP -LocalPort 546 -Action Block
```

## What might break

- L2 guards: nothing if configured correctly. Test on one switch first.
- `DisabledComponents = 0x20`: nothing in typical environments.
- `DisabledComponents = 0xFF` (avoid): Outlook profile creation, Exchange management tools, Failover Cluster, DirectAccess, parts of Windows Setup. Don't do this.

## Rollback

Switch config: remove the `dhcp guard` / `raguard` policies from the affected ports.
Registry: delete the `DisabledComponents` value or set to `0`. Reboot.

## Validate the fix

From an attacker host: run `mitm6 -d <yourdomain>` and watch. With L2 guards, the rogue DHCPv6 advertisement should be dropped before it reaches any client. Without L2 guards but with the registry mitigation, clients should not accept the rogue DNS server.

```powershell
# On a client, confirm the DNS server list does not include the attacker IP
Get-DnsClientServerAddress
```

## References

- mitm6 project: https://github.com/dirkjanm/mitm6
- Microsoft: [Guidance for configuring IPv6 in Windows](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows)
- Cisco: [IPv6 First-Hop Security](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipv6_fhsec/configuration/15-mt/ip6f-15-mt-book.html)
- MITRE ATT&CK: T1557.001
