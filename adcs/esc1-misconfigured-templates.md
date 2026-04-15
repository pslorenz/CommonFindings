# ESC1 — Misconfigured Certificate Templates (Subject Supplied in Request)

**Category:** Active Directory Certificate Services
**Operational Risk of Remediation:** Low (per-template)
**Attacker Skill Required to Exploit:** Low (Certipy, Certify)

## What it is

If an AD CS certificate template allows the requester to specify the Subject (or Subject Alternative Name), allows client authentication EKU, and is enrollable by low-privileged users — then any user can request a certificate with `userPrincipalName=Administrator@example.local`, receive a valid cert, and authenticate as that user.

This is "ESC1" in the SpecterOps AD CS attack taxonomy. ESC1 through ESC11+ are different misconfigurations of the same product. ESC1 is the most common.

## What attack it enables

Any domain user requests a certificate as Domain Admin → uses the certificate to obtain a TGT as Domain Admin → game over.

MITRE ATT&CK: T1649

## How to confirm it's present in your environment

Use **Certipy** (Linux) or **Certify** (Windows) to enumerate templates and find vulnerable ones:

```bash
# Certipy
certipy find -u user@example.local -p Password -dc-ip <dc-ip> -enabled -vulnerable
```

```powershell
# Certify
.\Certify.exe find /vulnerable
```

Either tool flags ESC1-vulnerable templates explicitly. Look for templates where:
- `mspki-certificate-name-flag` includes `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (1)
- `pkiextendedkeyusage` includes Client Authentication (1.3.6.1.5.5.7.3.2), PKINIT (1.3.6.1.5.2.3.4), Smart Card Logon (1.3.6.1.4.1.311.20.2.2), or Any Purpose (2.5.29.37.0)
- Enrollment rights granted to broad groups (Domain Users, Authenticated Users, Domain Computers)
- Manager approval not required
- No "authorized signature" requirement

## What to audit before remediation

For each vulnerable template:
1. Is it actually used? Check the CA database for issued certificates from this template:
   ```powershell
   certutil -view -restrict "Disposition=20,CertificateTemplate=<template-oid>" -out "RequesterName,NotBefore,NotAfter"
   ```
2. Who's enrolling it? Are those legitimate uses?
3. Could the legitimate use case be served by a more restrictive template?

## Remediation

For each ESC1-vulnerable template, do **at least one** of the following:

**1. Remove the "Supply in the request" subject option** (the cleanest fix):
- Open Certificate Templates Console (`certtmpl.msc`)
- Find the template → Properties → Subject Name tab
- Select "Build from this Active Directory information" instead of "Supply in the request"
- Apply

**2. Restrict enrollment to a small group** (Domain Computers, Domain Users, Authenticated Users should never have enroll rights on a template that issues client auth certs with arbitrary subjects):
- Template Properties → Security → remove broad groups, add specific service group only

**3. Require manager approval:**
- Template Properties → Issuance Requirements → check "CA certificate manager approval"

**4. If the template is unused, remove it from the CA's "Certificate Templates to Issue" list:**
- Open `certsrv.msc` → Certificate Templates → right-click → Manage → remove

**5. As a domain-wide hardening for ALL templates: enforce the May 2022 patches (KB5014754) Enforcement mode**, which requires strong certificate-to-account mapping:
- Set `HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 2` on all DCs
- This breaks any cert whose subject doesn't strongly map to an AD account, defeating ESC1 in many scenarios even if templates remain misconfigured.
- **Audit first**: there's an Audit mode (value `1`) — leave it there for a few weeks and watch Event ID 39 in the Kerberos-Key-Distribution-Center log to find any legitimate certs that would break.

## What might break

- If you change a template that an actual workflow uses (e.g., a custom auto-enrollment for VPN), that workflow will break. Always identify legitimate use first.
- Strong certificate binding enforcement (item 5) can break certificates issued by external/non-AD CAs that don't have the SID extension. Audit before enforcing.

## Rollback

Re-enable the template option you changed. Re-issue from the CA. Effective immediately for new requests.

## Validate the fix

Re-run `certipy find -vulnerable` — affected templates should no longer appear in the vulnerable list.

Attempt the attack as a low-priv user:
```bash
certipy req -u lowpriv@example.local -p Pass -ca <ca-name> -template <template> -upn administrator@example.local
# Should be denied
```

## References

- SpecterOps: [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) — the original ESC1-ESC8 paper
- Microsoft: [KB5014754 — Certificate-based authentication changes on Windows DCs](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- Certipy: https://github.com/ly4k/Certipy
- MITRE ATT&CK: T1649
