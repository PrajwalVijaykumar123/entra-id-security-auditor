"""
Parsers for real Microsoft Graph API export shapes. Three separate
real endpoints feed this tool, and their fields are NOT the same shape
as each other - this module keeps each one's real field names intact
rather than inventing one unified schema at the parsing stage (that
happens in checks.py, after joining them):

  - GET /identity/conditionalAccess/policies
      -> list of CA policy objects: {displayName, state, conditions:
         {clientAppTypes, users:{...}, applications:{...}}, grantControls:
         {builtInControls}}

  - GET /reports/authenticationMethods/userRegistrationDetails
      -> the REAL Graph "per-user MFA registration" reporting endpoint.
         Fields: userPrincipalName, userType, isAdmin, isMfaRegistered,
         isMfaCapable, isSsprRegistered, lastUpdatedDateTime.
         NOTE: isAdmin here just means "holds at least one directory
         role", not specifically Global Administrator - checks.py cross-
         references the actual role name separately via role_assignments.

  - A role-assignment export (modeled on roleManagement/directoryRoleAssignments
      joined with its roleDefinition and principal, which Graph returns as
      separate objects that must be joined by id in a real client - here
      flattened to one row per assignment for simplicity):
      {roleDisplayName, principalUserPrincipalName, assignmentType
       ("Eligible" | "Active" - the real Entra PIM distinction between a
       just-in-time-activatable assignment and a standing/permanent one),
       lastSignInDateTime}
"""
from dataclasses import dataclass, field


@dataclass
class CAPolicy:
    display_name: str
    state: str                     # "enabled" | "disabled" | "enabledForReportingButNotEnforced"
    client_app_types: list
    built_in_controls: list
    include_users: list


@dataclass
class UserRegistration:
    user_principal_name: str
    user_type: str                 # "Member" | "Guest"
    is_admin: bool
    is_mfa_registered: bool
    last_updated: str


@dataclass
class RoleAssignment:
    role_display_name: str
    principal_upn: str
    assignment_type: str           # "Eligible" | "Active"
    last_sign_in: str


def load_ca_policies(raw: list) -> list:
    out = []
    for p in raw:
        cond = p.get("conditions", {}) or {}
        grant = p.get("grantControls", {}) or {}
        users = cond.get("users", {}) or {}
        out.append(CAPolicy(
            display_name=p["displayName"],
            state=p.get("state", "disabled"),
            client_app_types=cond.get("clientAppTypes", []) or [],
            built_in_controls=grant.get("builtInControls", []) or [],
            include_users=users.get("includeUsers", []) or [],
        ))
    return out


def load_user_registrations(raw: list) -> list:
    return [
        UserRegistration(
            user_principal_name=u["userPrincipalName"],
            user_type=u.get("userType", "Member"),
            is_admin=bool(u.get("isAdmin", False)),
            is_mfa_registered=bool(u.get("isMfaRegistered", False)),
            last_updated=u.get("lastUpdatedDateTime", ""),
        )
        for u in raw
    ]


def load_role_assignments(raw: list) -> list:
    return [
        RoleAssignment(
            role_display_name=r["roleDisplayName"],
            principal_upn=r["principalUserPrincipalName"],
            assignment_type=r.get("assignmentType", "Active"),
            last_sign_in=r.get("lastSignInDateTime", ""),
        )
        for r in raw
    ]
