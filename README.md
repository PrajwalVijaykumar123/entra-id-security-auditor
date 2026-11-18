# Entra ID Security Auditor

Audits real Microsoft Graph-shaped Entra ID (Azure AD) exports for **7 identity-security checks**, cross-referencing three separate Graph data sources the way a real audit has to: Conditional Access policies, per-user MFA registration status, and privileged role assignments.

## Why Three Separate Data Sources, Joined

Microsoft Graph doesn't hand you one combined "is this tenant secure" export - it hands you three independent resources from three independent endpoints, and a real auditor (human or tool) has to join them by `userPrincipalName` to ask the question that actually matters: *is the person holding Global Administrator one of the people who registered MFA?* Checking each source in isolation misses that - a tenant could have MFA registration at 100% and still have its one unregistered holdout be the Global Administrator. This tool does the join explicitly:

- `GET /identity/conditionalAccess/policies` - tenant-wide Conditional Access policies
- `GET /reports/authenticationMethods/userRegistrationDetails` - the real Graph reporting endpoint for per-user MFA registration status (`isMfaRegistered`, `isAdmin`, `userType`)
- A privileged role assignment export (modeled on `roleManagement/directoryRoleAssignments` joined with its role definition and principal, which Graph returns as separate objects in a real client) - including the real Entra **PIM** distinction between an `Eligible` (just-in-time, activated on demand) and an `Active` (standing, always-on) assignment

## What This Project Checks

| ID | Check | Severity |
|---|---|---|
| ENTRA-1 | No enabled Conditional Access policy blocks legacy authentication (`clientAppTypes` containing `"other"`) | Critical |
| ENTRA-2 | No enabled Conditional Access policy requires MFA for any user | Critical |
| ENTRA-3 | A user holding a privileged role (Global Administrator, Privileged Role Administrator, Security Administrator) has not registered MFA | Critical |
| ENTRA-4 | A Guest account holds a privileged role | Critical |
| ENTRA-5 | A privileged role is assigned as permanent/standing (`Active`) rather than PIM-eligible (`Eligible`) | High |
| ENTRA-6 | A privileged role holder hasn't signed in within the staleness threshold (default 45 days) - or has no recorded sign-in at all | Medium |
| ENTRA-7 | Any admin (`isAdmin: true`) has not registered MFA, independent of which specific role they hold | Critical |

ENTRA-3/4/5/6 specifically target the three named **privileged** roles (`PRIVILEGED_ROLES` in `checks.py`) rather than all ~90 Entra directory roles - a short, deliberately curated list of the roles that actually carry tenant-wide blast radius, so the audit isn't buried under findings about roles like "Printer Administrator" that don't matter for this purpose.

## Relationship to This Portfolio's Other Identity Tools

- **`iam-privileged-access-auditor`** audits **local** Linux (`sudo`/group membership) and Windows (`net localgroup`) privileged access - no cloud identity provider involved at all.
- **`intune-device-compliance-auditor`** audits **device** compliance (encryption, jailbreak status, OS version) via Graph's `managedDevices` endpoint - a different Graph resource entirely, about devices, not identities.
- **This tool** is the one that actually covers Entra ID / M365 identity governance: Conditional Access, MFA enforcement, and cloud privileged-role hygiene - distinct from all three of the above.

## Tech Stack

- Python 3.11, standard library only (`dataclasses`, `argparse`, `json`, `datetime`) - no third-party dependencies

## Setup

```bash
python3 scanner.py --ca-policies ca.json --user-registrations users.json --role-assignments roles.json
python3 scanner.py --ca-policies ca.json --user-registrations users.json --role-assignments roles.json \
    --stale-days 30 --json report.json --fail-on critical
```

`--reference-date` accepts an ISO8601 timestamp to make staleness checks reproducible (used by the test suite); omitted, it defaults to the real current time.

## Testing

`test_fixtures/` contains a compliant triple (legacy auth blocked, MFA required tenant-wide, the one Global Administrator is MFA-registered, PIM-eligible, and recently signed in) and a noncompliant triple exercising all 7 checks at once: no legacy-auth block, no MFA-required policy, the Global Administrator has no MFA registered, is a standing (`Active`) assignment, hasn't signed in for 170 days, and a Guest account separately holds `Privileged Role Administrator`. `run_test.sh` runs the real scanner against both:

```bash
sh test_fixtures/run_test.sh
```

11 assertions, all passing - the compliant triple produces zero findings and exits 0; the noncompliant triple fires all 7 checks and exits 1.

## Architecture

```
scanner.py (CLI: report formatting, --fail-on exit codes)
        |
        v
graph_parser.py: loads 3 separate real Graph export shapes
    (CAPolicy / UserRegistration / RoleAssignment)
        |
        v
checks.py: 7 checks, several of which JOIN role_assignments against
    user_registrations by userPrincipalName before evaluating
        |
        v
Console report (grouped by severity) + optional JSON; exit code reflects --fail-on
```

## Project Structure

```
entra-id-security-auditor/
├── scanner.py                               # CLI
├── graph_parser.py                          # 3 real Graph export-shape loaders
├── checks.py                                # 7 checks, several cross-referencing sources
└── test_fixtures/
    ├── compliant_ca_policies.json
    ├── compliant_user_registrations.json
    ├── compliant_role_assignments.json
    ├── noncompliant_ca_policies.json
    ├── noncompliant_user_registrations.json
    ├── noncompliant_role_assignments.json
    └── run_test.sh                          # Runs scanner.py against both triples
```

## What I Learned

- Graph's `isAdmin` field on `userRegistrationDetails` means "holds at least one directory role" - it is NOT specific to Global Administrator. I initially conflated the two while sketching the checks, which would have meant ENTRA-3 silently never distinguishing a genuinely critical role from a low-impact one; keeping ENTRA-7 (any admin, any role) and ENTRA-3 (specifically the named privileged roles, cross-referenced against the separate role-assignment export) as two distinct checks is what actually captures Graph's real field semantics correctly.
- The `Eligible` vs `Active` PIM distinction (ENTRA-5) is a genuinely different risk dimension from "is this role assignment correct at all" - a user can legitimately need Global Administrator access and still be a finding if that access is standing rather than just-in-time, because standing access is what gets compromised silently in a credential-theft scenario while PIM-eligible access requires an explicit activation step that shows up in logs.
- Designing the test fixtures required working out, before writing a single assertion, exactly which of the 7 checks each of the two noncompliant-side records needed to trigger simultaneously (the Global Administrator triggers ENTRA-3/5/6/7 on their own; the separate Guest-held role triggers ENTRA-4 alone) - getting that overlap deliberate rather than accidental is what let one small fixture set exercise all 7 checks without needing seven separate noncompliant files.

## Next Steps

- A check for Conditional Access policies that exclude "break-glass" emergency-access accounts, since those accounts' exclusion is a real, deliberate Microsoft-recommended practice that an automated "every policy should apply to All users" check would incorrectly flag.
- Live Graph API integration (via `msal`/`requests` with proper app registration and least-privilege Graph scopes) so this could run as a real scheduled compliance check against an actual tenant, rather than only against exported JSON.
- Feed this tool's findings into `bsi-compliance-aggregator` as a sixth adapter - MFA enforcement and privileged-access hygiene map naturally onto BSI's `ORP.4` (Identity and Access Management) Baustein, already used by two other tools in this portfolio.
