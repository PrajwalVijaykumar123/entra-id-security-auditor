"""
7 checks over the three joined Entra ID data sources. The interesting
engineering here is the JOIN between role_assignments and
user_registrations by userPrincipalName - Graph returns these as
separate resources from separate endpoints, so any real tool doing this
audit has to correlate them itself; this module does that correlation
explicitly rather than assuming one combined export.

PRIVILEGED_ROLES is deliberately a short, real list of the Entra roles
that matter most for this kind of audit - "every role" would bury the
3 that actually carry tenant-wide blast radius under the ~90 roles Entra
actually ships.
"""
from dataclasses import dataclass
from datetime import datetime, timezone

STALE_SIGNIN_DAYS_DEFAULT = 45

PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
}


@dataclass
class Finding:
    check_id: str
    severity: str           # "critical" | "high" | "medium" | "low"
    iso27001_ref: str
    message: str


def _parse_dt(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def check_legacy_auth_blocked(ca_policies: list) -> list:
    # "other" is Graph's real clientAppTypes value for legacy authentication
    # protocols (basic auth / non-modern clients) that can't respond to an
    # MFA challenge at all - a policy targeting it with a "block" grant
    # control is Microsoft's own documented baseline recommendation.
    for p in ca_policies:
        if (p.state == "enabled"
                and "other" in p.client_app_types
                and "block" in [c.lower() for c in p.built_in_controls]):
            return []
    return [Finding(
        "ENTRA-1", "critical", "A.9.4.2",
        "No enabled Conditional Access policy blocks legacy authentication "
        "(clientAppTypes containing \"other\") - legacy protocols bypass MFA "
        "entirely because they cannot respond to an MFA challenge.",
    )]


def check_mfa_required_for_all_users(ca_policies: list) -> list:
    for p in ca_policies:
        if p.state == "enabled" and "mfa" in p.built_in_controls:
            return []
    return [Finding(
        "ENTRA-2", "critical", "A.9.4.2",
        "No enabled Conditional Access policy requires MFA - there is no "
        "tenant-wide enforcement point for multi-factor authentication.",
    )]


def check_privileged_roles_require_mfa(role_assignments: list, registrations: list) -> list:
    reg_by_upn = {r.user_principal_name: r for r in registrations}
    findings = []
    for ra in role_assignments:
        if ra.role_display_name not in PRIVILEGED_ROLES:
            continue
        reg = reg_by_upn.get(ra.principal_upn)
        if reg is None or not reg.is_mfa_registered:
            findings.append(Finding(
                "ENTRA-3", "critical", "A.9.2.4",
                f"{ra.principal_upn} holds the privileged role "
                f"'{ra.role_display_name}' but has NOT registered MFA.",
            ))
    return findings


def check_guests_not_privileged(role_assignments: list, registrations: list) -> list:
    reg_by_upn = {r.user_principal_name: r for r in registrations}
    findings = []
    for ra in role_assignments:
        if ra.role_display_name not in PRIVILEGED_ROLES:
            continue
        reg = reg_by_upn.get(ra.principal_upn)
        if reg is not None and reg.user_type == "Guest":
            findings.append(Finding(
                "ENTRA-4", "critical", "A.9.2.3",
                f"Guest account {ra.principal_upn} holds the privileged "
                f"role '{ra.role_display_name}'.",
            ))
    return findings


def check_standing_privileged_access(role_assignments: list) -> list:
    findings = []
    for ra in role_assignments:
        if ra.role_display_name in PRIVILEGED_ROLES and ra.assignment_type == "Active":
            findings.append(Finding(
                "ENTRA-5", "high", "A.9.2.3",
                f"{ra.principal_upn} has a permanent/standing ('Active') "
                f"assignment to '{ra.role_display_name}' instead of a "
                f"just-in-time PIM-eligible assignment.",
            ))
    return findings


def check_stale_privileged_accounts(role_assignments: list, reference_time=None,
                                     stale_days: int = STALE_SIGNIN_DAYS_DEFAULT) -> list:
    reference_time = reference_time or datetime.now(timezone.utc)
    findings = []
    for ra in role_assignments:
        if ra.role_display_name not in PRIVILEGED_ROLES:
            continue
        last = _parse_dt(ra.last_sign_in)
        if last is None:
            findings.append(Finding(
                "ENTRA-6", "medium", "A.9.2.6",
                f"{ra.principal_upn} ('{ra.role_display_name}') has no recorded sign-in at all.",
            ))
            continue
        age_days = (reference_time - last).days
        if age_days > stale_days:
            findings.append(Finding(
                "ENTRA-6", "medium", "A.9.2.6",
                f"{ra.principal_upn} ('{ra.role_display_name}') last signed in "
                f"{age_days} days ago (threshold: {stale_days}) - review for removal.",
            ))
    return findings


def check_admins_without_mfa(registrations: list) -> list:
    return [
        Finding(
            "ENTRA-7", "critical", "A.9.4.2",
            f"{r.user_principal_name} holds at least one directory role "
            f"but has NOT registered MFA.",
        )
        for r in registrations
        if r.is_admin and not r.is_mfa_registered
    ]


def run_all(ca_policies, registrations, role_assignments, reference_time=None,
            stale_days: int = STALE_SIGNIN_DAYS_DEFAULT) -> list:
    findings = []
    findings += check_legacy_auth_blocked(ca_policies)
    findings += check_mfa_required_for_all_users(ca_policies)
    findings += check_privileged_roles_require_mfa(role_assignments, registrations)
    findings += check_guests_not_privileged(role_assignments, registrations)
    findings += check_standing_privileged_access(role_assignments)
    findings += check_stale_privileged_accounts(role_assignments, reference_time, stale_days)
    findings += check_admins_without_mfa(registrations)
    return findings
