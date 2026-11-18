#!/usr/bin/env python3
"""
entra-id-security-auditor: audits real Microsoft Graph-shaped Entra ID
exports (Conditional Access policies, per-user MFA registration, and
privileged role assignments) and cross-references them against each
other for 7 real identity-security checks.
"""
import argparse
import json
import sys
from datetime import datetime, timezone

from graph_parser import load_ca_policies, load_user_registrations, load_role_assignments
from checks import run_all, STALE_SIGNIN_DAYS_DEFAULT

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def render_console(findings):
    if not findings:
        return "No findings - all checks passed."
    lines = []
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity), reverse=True):
        lines.append(f"[{f.severity.upper():<8}] {f.check_id} ({f.iso27001_ref}): {f.message}")
    return "\n".join(lines)


def to_json(findings):
    return [
        {"check_id": f.check_id, "severity": f.severity, "iso27001_ref": f.iso27001_ref, "message": f.message}
        for f in findings
    ]


def main():
    ap = argparse.ArgumentParser(description="Audit Entra ID Conditional Access, MFA, and privileged role data")
    ap.add_argument("--ca-policies", required=True, help="Conditional Access policies export (JSON)")
    ap.add_argument("--user-registrations", required=True, help="userRegistrationDetails export (JSON)")
    ap.add_argument("--role-assignments", required=True, help="Privileged role assignments export (JSON)")
    ap.add_argument("--reference-date", help="ISO8601 'now' for reproducible staleness checks")
    ap.add_argument("--stale-days", type=int, default=STALE_SIGNIN_DAYS_DEFAULT)
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "any"], default=None)
    args = ap.parse_args()

    with open(args.ca_policies) as fh:
        ca_policies = load_ca_policies(json.load(fh))
    with open(args.user_registrations) as fh:
        registrations = load_user_registrations(json.load(fh))
    with open(args.role_assignments) as fh:
        role_assignments = load_role_assignments(json.load(fh))

    reference_time = (
        datetime.fromisoformat(args.reference_date.replace("Z", "+00:00"))
        if args.reference_date else datetime.now(timezone.utc)
    )

    findings = run_all(ca_policies, registrations, role_assignments, reference_time, args.stale_days)

    print(render_console(findings))
    print(f"\n{len(findings)} finding(s).")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(findings), fh, indent=2)

    if args.fail_on:
        if args.fail_on == "any":
            trigger_idx = 0
        else:
            trigger_idx = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) >= trigger_idx for f in findings):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
