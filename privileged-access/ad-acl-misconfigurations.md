# AD ACL Misconfigurations (BloodHound Attack Paths)

**Category:** Privileged Access
**Operational Risk of Remediation:** Medium (depends on the ACL — some are clearly garbage, others may be legitimate-but-undocumented)
**Attacker Skill Required to Exploit:** Low (BloodHound shows the path; tooling executes it)

## What it is

Active Directory permissions ("ACLs") on objects determine who can do what to whom. Over years of "just give them what they asked for" ticket resolution, environments accumulate ACLs that grant non-privileged users dangerous rights on privileged objects:

- **GenericAll / GenericWrite** on a user → reset their password, add SPN to kerberoast, etc.
- **WriteDACL** on an object → grant yourself any permission, then exercise it.
- **WriteOwner** on an object → make yourself owner, then grant yourself rights.
- **ForceChangePassword** on a user → change their password without knowing the old one.
- **AddMember** on a group → add yourself to it (and if it's Domain Admins, game over).
- **AllExtendedRights** on a user → includes ForceChangePassword.
- **WriteSPN** on a user → add an SPN, then kerberoast.
- **AddKeyCredentialLink** on a user/computer → "Shadow Credentials" attack: add a public key, request a TGT as them via PKINIT.

These individually look harmless. Chained, they become attack paths from "Domain Users" to "Domain Admins" in three to five hops. BloodHound exists specifically to find these chains.

## What attack it enables

Privilege escalation along the ACL graph. The attacker's path is fully visible in BloodHound — no novel exploitation required, just abuse of the rights that already exist.

MITRE ATT&CK: T1078, T1098

## How to confirm it's present in your environment

**Run BloodHound.** It is the industry-standard tool for finding these paths and is free.

1. Install BloodHound CE (Community Edition) — Docker compose makes it 10 minutes.
2. Run **SharpHound** (Windows) or **bloodhound.py** / **bloodhound-ce.py** (Linux) as a low-priv domain user:
   ```
   SharpHound.exe -c All
   # or
   bloodhound-ce-python -u user -p Pass -d example.local -ns <dc-ip> -c All
   ```
3. Import the resulting JSON into BloodHound.
4. Run the built-in queries:
   - **Shortest Paths to Domain Admins** — the headline finding
   - **Shortest Paths to High Value Targets**
   - **Shortest Paths from Owned Principals**
   - **Find Principals with DCSync Rights**
   - **Find Computers with Unconstrained Delegation**
   - **Shadow Credentials** queries

If any path exists from "Domain Users" / "Authenticated Users" / large groups to a tier 0 object, that path needs to be cut.

For a one-shot defender check without BloodHound, **PingCastle** and **Purple Knight** both audit AD ACLs and produce ranked reports. PingCastle is free for non-commercial use and is the fastest way to a baseline.

## What to audit before remediation

Each ACL finding falls into one of three buckets:

1. **Obviously wrong** — "Domain Users has GenericAll on Domain Admins" type stuff. Just remove it.
2. **Legitimate but over-scoped** — a help-desk group has ResetPassword on the entire domain when it should only need it on a specific OU. Re-scope.
3. **Legitimate and necessary** — usually scoped delegation that's been documented somewhere. Confirm with the team that requested it.

For each finding, before removing the ACL:
- **Look at the object owner**: `Get-Acl "AD:\<DN>"` shows who owns it. Sometimes the owner is the original problem.
- **Ask "who set this and why"**: change history isn't logged unless you've enabled DS object access auditing, but the principal that holds the right may be a clue (e.g., a long-departed contractor).
- **Check whether the right is actually used**: enable directory service auditing for the object (`SACL` entry for the principal) and watch for use over a couple weeks.

## Remediation

For each unwanted ACE:

```powershell
# View ACL on an object
$acl = Get-Acl "AD:\CN=Domain Admins,CN=Users,DC=example,DC=local"
$acl.Access | Where-Object { $_.IdentityReference -match 'BadGroup' }

# Remove a specific ACE
$badAce = $acl.Access | Where-Object { $_.IdentityReference -match 'BadGroup' -and $_.ActiveDirectoryRights -match 'GenericAll' }
$acl.RemoveAccessRule($badAce)
Set-Acl -Path "AD:\CN=Domain Admins,CN=Users,DC=example,DC=local" -AclObject $acl
```

**At scale**: it's much easier to use the GUI for individual changes (ADUC → Advanced Features → object Properties → Security tab) and PowerShell for bulk audit/inventory. Bulk ACE modifications via script are powerful and easy to break things with — go slow.

**Common cleanup patterns:**

- Remove `Authenticated Users` and `Everyone` from anywhere they don't belong.
- Remove ACEs granted to disabled or deleted accounts (orphaned SIDs).
- Move privileged groups (Domain Admins, etc.) under a **protected OU** with restrictive ACLs and link a GPO that overrides AdminSDHolder defaults appropriately.
- Verify **AdminSDHolder** itself (`CN=AdminSDHolder,CN=System,DC=...`) — its ACL is propagated to all "protected" objects every 60 minutes, so any garbage there spreads everywhere. Inspect carefully.

## What might break

- Removing an ACL that was actually being used by a service or process — symptom is "user/script suddenly can't do X." Easy to roll back.
- Changing AdminSDHolder is high-impact — propagates to every protected object. Test in a lab first if you can.

## Rollback

Re-add the ACE you removed:
```powershell
$acl = Get-Acl "AD:\..."
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(...)
$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\..." -AclObject $acl
```

For AdminSDHolder changes, propagation is hourly — wait or run `Invoke-Command` to trigger SDProp manually if needed.

## Validate the fix

Re-run SharpHound, re-import to BloodHound, and re-run the "Shortest Paths to Domain Admins" query. Paths that previously existed should be gone.

For ongoing assurance: schedule monthly BloodHound runs (or use BloodHound Enterprise / Adalanche / Purple Knight for continuous monitoring).

## References

- BloodHound: https://github.com/SpecterOps/BloodHound
- PingCastle: https://www.pingcastle.com/
- Adalanche: https://github.com/lkarlslund/Adalanche
- Will Schroeder & Andy Robbins: original BloodHound research and blog posts at posts.specterops.io
- MITRE ATT&CK: T1078, T1098
