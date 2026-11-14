#!/usr/bin/env python3
"""Generate a realistic sample data.js so the dashboard is demoable without Azure.
Schema mirrors what Invoke-AzAnalysis (AzIAM.psm1) emits."""
import json, random, uuid, datetime, sys, os

random.seed(7)
now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
TENANT = "11111111-2222-3333-4444-555555555555"
SUBID = "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

def gid(): return uuid.uuid4().hex[:12]

users = [
    ("Alice Admin", "alice@contoso.com", True, "Member"),
    ("Bob Builder", "bob@contoso.com", True, "Member"),
    ("Carol Contractor", "carol@partner.com", True, "Guest"),
    ("Dan DevOps", "dan@contoso.com", True, "Member"),
    ("Eve External", "eve@outside.com", True, "Guest"),
    ("Frank Finance", "frank@contoso.com", True, "Member"),
    ("Svc Legacy", "svc-legacy@contoso.com", False, "Member"),
]
groups = [("Cloud Admins", True), ("Developers", True), ("Finance", True)]
sps = [
    ("terraform-ci", "ServicePrincipal", 2, 1),
    ("backup-runner", "ServicePrincipal", 0, 1),
    ("legacy-app", "ServicePrincipal", 3, 0),
    ("vm-prod-mi", "ManagedIdentity", 0, 0),
    ("aks-kubelet-mi", "ManagedIdentity", 0, 0),
]

uid = {name: gid() for (name, *_ ) in users}
grp = {name: gid() for (name, *_ ) in groups}
spid = {name: gid() for (name, *_ ) in sps}

nodes, edges, findings, paths = [], [], [], []

def node(i, label, t, tier0=False, data=None):
    nodes.append({"id": i, "label": label, "type": t, "tier0": tier0, "data": data or {}})

for (name, upn, en, ut) in users:
    node(uid[name], name, "User", data={"upn": upn, "enabled": en, "userType": ut})
for (name, sec) in groups:
    node(grp[name], name, "Group", data={"securityEnabled": sec})
for (name, t, pw, kc) in sps:
    node(spid[name], name, t, data={"spType": t, "enabled": True, "passwordCreds": pw, "keyCreds": kc, "appId": gid()})

# directory roles
ga = "dirrole:Global Administrator"
appadmin = "dirrole:Application Administrator"
node(ga, "Global Administrator", "DirectoryRole", tier0=True)
node(appadmin, "Application Administrator", "DirectoryRole", tier0=True)
edges.append({"id": f"{uid['Alice Admin']}->{ga}->HasDirectoryRole", "source": uid["Alice Admin"], "target": ga, "type": "HasDirectoryRole", "label": "Global Administrator"})
edges.append({"id": f"{uid['Dan DevOps']}->{appadmin}->HasDirectoryRole", "source": uid["Dan DevOps"], "target": appadmin, "type": "HasDirectoryRole", "label": "Application Administrator"})

# group membership
for u in ["Bob Builder", "Dan DevOps"]:
    edges.append({"id": f"{uid[u]}->{grp['Cloud Admins']}->MemberOf", "source": uid[u], "target": grp["Cloud Admins"], "type": "MemberOf", "label": "member of"})
edges.append({"id": f"{uid['Frank Finance']}->{grp['Finance']}->MemberOf", "source": uid["Frank Finance"], "target": grp["Finance"], "type": "MemberOf", "label": "member of"})

# scope nodes
sub_scope = "scope:" + SUBID
node(sub_scope, "prod-subscription", "Subscription", tier0=True, data={"fullScope": SUBID})
rg_scope = "scope:" + SUBID + "/resourceGroups/rg-app"
node(rg_scope, "rg-app", "ResourceGroup", data={"fullScope": SUBID + "/resourceGroups/rg-app"})

role_assignments = []
def ra(principal_name, pid, ptype, role, scope):
    role_assignments.append({"principalName": principal_name, "principalType": ptype, "principalId": pid,
                             "role": role, "scope": scope, "subscription": SUBID.split("/")[-1]})
    sc_node = "scope:" + scope
    if not any(n["id"] == sc_node for n in nodes):
        lvl = "Subscription" if scope.count("/") == 2 else ("ResourceGroup" if "resourceGroups" in scope and scope.count("/") == 4 else "Resource")
        node(sc_node, scope.split("/")[-1], lvl, data={"fullScope": scope})
    edges.append({"id": f"{pid}->{sc_node}->HasRole", "source": pid, "target": sc_node, "type": "HasRole", "label": role})
    if role in ("Owner", "User Access Administrator"):
        nd = next(n for n in nodes if n["id"] == sc_node); nd["tier0"] = True
        edges.append({"id": f"{pid}->{sc_node}->CanEscalate", "source": pid, "target": sc_node, "type": "CanEscalate", "label": "can grant roles"})

ra("Cloud Admins", grp["Cloud Admins"], "Group", "Owner", SUBID)
ra("terraform-ci", spid["terraform-ci"], "ServicePrincipal", "Contributor", SUBID)
ra("legacy-app", spid["legacy-app"], "ServicePrincipal", "User Access Administrator", SUBID)
ra("Carol Contractor", uid["Carol Contractor"], "User", "Contributor", SUBID + "/resourceGroups/rg-app")
ra("Frank Finance", uid["Frank Finance"], "User", "Reader", SUBID)
ra("vm-prod-mi", spid["vm-prod-mi"], "ManagedIdentity", "Contributor", SUBID + "/resourceGroups/rg-app")
ra("backup-runner", spid["backup-runner"], "ServicePrincipal", "Backup Contributor", SUBID + "/resourceGroups/rg-app")

# app ownership control edge (Dan owns legacy-app SP -> can add creds)
edges.append({"id": f"{uid['Dan DevOps']}->{spid['legacy-app']}->CanControl", "source": uid["Dan DevOps"], "target": spid["legacy-app"], "type": "CanControl", "label": "app owner (add credential)"})

def finding(sev, cat, title, desc, principal, ptype, ev, rec, refs):
    findings.append({"id": gid()[:12], "severity": sev, "category": cat, "title": title, "description": desc,
                     "principal": principal, "principalType": ptype, "evidence": ev, "recommendation": rec, "references": refs})

finding("Critical", "Privileged Access", "Tier-0 Entra role: Global Administrator",
        "Identity holds the highly privileged Entra ID role 'Global Administrator', granting broad control over the directory.",
        "Alice Admin", "User", "Directory role 'Global Administrator'",
        "Enforce PIM just-in-time activation, require phishing-resistant MFA, minimize standing Global Admins (<5).",
        ["https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"])
finding("Critical", "Privilege Escalation", "User Access Administrator at Subscription scope",
        "'legacy-app' holds 'User Access Administrator' at a Subscription scope, allowing it to assign roles (including to itself). Assigned to a service principal — credential theft directly yields this privilege.",
        "legacy-app", "ServicePrincipal", "User Access Administrator @ " + SUBID,
        "Apply least privilege; use PIM for eligible assignment; review Owner/UAA holders quarterly.",
        ["https://learn.microsoft.com/azure/role-based-access-control/best-practices"])
finding("Critical", "Attack Path", "Attack path to Tier-0: Dan DevOps -> prod-subscription",
        "A multi-step control path reaches a tier-0 asset: Dan DevOps -> [app owner (add credential)] legacy-app -> [can grant roles] prod-subscription",
        "Dan DevOps", "Identity", "Dan DevOps -> legacy-app -> prod-subscription",
        "Break the chain: remove app ownership or the broad UAA role along this path.",
        ["https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model"])
finding("High", "Privilege Escalation", "Owner at Subscription scope",
        "'Cloud Admins' holds 'Owner' at a Subscription scope, allowing full control and role assignment.",
        "Cloud Admins", "Group", "Owner @ " + SUBID,
        "Convert to PIM-eligible; audit group membership (currently includes Bob, Dan).",
        ["https://learn.microsoft.com/azure/role-based-access-control/best-practices"])
finding("High", "Privileged Access", "Contributor at Subscription scope",
        "'terraform-ci' holds 'Contributor' across the entire subscription.",
        "terraform-ci", "ServicePrincipal", "Contributor @ " + SUBID,
        "Scope Contributor to specific resource groups instead of the whole subscription.",
        ["https://learn.microsoft.com/azure/role-based-access-control/best-practices"])
finding("Medium", "External Access", "Guest user holds Azure RBAC role",
        "Guest (external) user 'Carol Contractor' has 'Contributor' on rg-app.",
        "Carol Contractor", "Guest", "Contributor @ rg-app",
        "Review B2B guest access; restrict guest role assignments; use access reviews.",
        ["https://learn.microsoft.com/entra/identity/users/users-restrict-guest-permissions"])
finding("Low", "Credential Hygiene", "Service principal has expired secrets: legacy-app",
        "App/SP 'legacy-app' has 2 expired client secret(s) still present.",
        "legacy-app", "ServicePrincipal", "2 expired secrets",
        "Remove unused credentials; prefer workload identity federation.",
        ["https://learn.microsoft.com/entra/workload-id/workload-identity-federation"])

paths = [
    {"id": gid()[:8], "title": "Dan DevOps -> prod-subscription", "start": "Dan DevOps", "target": "prod-subscription",
     "severity": "Critical", "length": 2,
     "steps": ["Dan DevOps", "[app owner (add credential)] legacy-app", "[can grant roles] prod-subscription"]},
    {"id": gid()[:8], "title": "Bob Builder -> prod-subscription", "start": "Bob Builder", "target": "prod-subscription",
     "severity": "Critical", "length": 2,
     "steps": ["Bob Builder", "[member of] Cloud Admins", "[can grant roles] prod-subscription"]},
    {"id": gid()[:8], "title": "Alice Admin -> Global Administrator", "start": "Alice Admin", "target": "Global Administrator",
     "severity": "High", "length": 1, "steps": ["Alice Admin", "[Global Administrator] Global Administrator"]},
]

resources = [
    {"name": "vm-prod-01", "type": "Microsoft.Compute/virtualMachines", "resourceGroup": "rg-app", "location": "eastus", "subscription": SUBID.split("/")[-1]},
    {"name": "kv-prod-secrets", "type": "Microsoft.KeyVault/vaults", "resourceGroup": "rg-app", "location": "eastus", "subscription": SUBID.split("/")[-1]},
    {"name": "stproddata001", "type": "Microsoft.Storage/storageAccounts", "resourceGroup": "rg-app", "location": "eastus", "subscription": SUBID.split("/")[-1]},
    {"name": "aks-prod", "type": "Microsoft.ContainerService/managedClusters", "resourceGroup": "rg-infra", "location": "eastus", "subscription": SUBID.split("/")[-1]},
    {"name": "sql-finance", "type": "Microsoft.Sql/servers", "resourceGroup": "rg-fin", "location": "eastus", "subscription": SUBID.split("/")[-1]},
]

identities = [n for n in nodes if n["type"] in ("User", "Group", "ServicePrincipal", "ManagedIdentity")]
dir_roles = [
    {"roleName": "Global Administrator", "memberCount": 1, "members": ["Alice Admin"]},
    {"roleName": "Application Administrator", "memberCount": 1, "members": ["Dan DevOps"]},
    {"roleName": "Security Reader", "memberCount": 0, "members": []},
]

RG_APP = SUBID + "/resourceGroups/rg-app"
sp_right_sizing = [
    {"id": spid["legacy-app"], "appId": next(n["data"]["appId"] for n in nodes if n["id"] == spid["legacy-app"]),
     "displayName": "legacy-app", "type": "ServicePrincipal", "enabled": True,
     "verdict": "ReviewGraph", "overprivilege": 96,
     "grantedRoles": [{"role": "User Access Administrator", "scope": SUBID, "scopeLevel": "Subscription", "exercised": False, "writeCapable": True}],
     "graphPermissions": [{"permission": "Directory.ReadWrite.All", "api": "Microsoft Graph", "highRisk": True},
                          {"permission": "Application.ReadWrite.All", "api": "Microsoft Graph", "highRisk": True},
                          {"permission": "User.Read.All", "api": "Microsoft Graph", "highRisk": False}],
     "usage": {"analyzed": True, "windowDays": 90, "totalOperations": 0, "distinctOps": 0, "readOnly": False,
               "lastActivity": None, "scopesUsed": [], "operations": []},
     "recommendations": ["No control-plane activity in the last 90 days. Candidate to remove RBAC or disable the SP.",
                         "Holds high-risk Graph application permission(s): Directory.ReadWrite.All, Application.ReadWrite.All. These bypass RBAC entirely — remove any not required."],
     "remediation": ['az role assignment delete --assignee <appId> --role "User Access Administrator" --scope "' + SUBID + '"',
                     "# Review/remove Graph app permission 'Directory.ReadWrite.All' in Entra > App registrations > legacy-app > API permissions"]},
    {"id": spid["terraform-ci"], "appId": next(n["data"]["appId"] for n in nodes if n["id"] == spid["terraform-ci"]),
     "displayName": "terraform-ci", "type": "ServicePrincipal", "enabled": True,
     "verdict": "ScopeReduction", "overprivilege": 75,
     "grantedRoles": [{"role": "Contributor", "scope": SUBID, "scopeLevel": "Subscription", "exercised": True, "writeCapable": True}],
     "graphPermissions": [],
     "usage": {"analyzed": True, "windowDays": 90, "totalOperations": 412, "distinctOps": 9, "readOnly": False,
               "lastActivity": now, "scopesUsed": [RG_APP],
               "operations": [{"op": "Microsoft.Resources/deployments/write", "count": 180, "lastUsed": now, "scopes": [RG_APP]},
                              {"op": "Microsoft.Storage/storageAccounts/write", "count": 44, "lastUsed": now, "scopes": [RG_APP]}]},
     "recommendations": ["Activity is confined to 1 resource group (rg-app) but the role is granted subscription-wide. Re-scope to just that RG."],
     "remediation": ['az role assignment create --assignee <appId> --role "Contributor" --scope "' + RG_APP + '"',
                     'az role assignment delete --assignee <appId> --role "Contributor" --scope "' + SUBID + '"']},
    {"id": spid["backup-runner"], "appId": next(n["data"]["appId"] for n in nodes if n["id"] == spid["backup-runner"]),
     "displayName": "backup-runner", "type": "ServicePrincipal", "enabled": True,
     "verdict": "ReadOnly", "overprivilege": 85,
     "grantedRoles": [{"role": "Backup Contributor", "scope": RG_APP, "scopeLevel": "ResourceGroup", "exercised": True, "writeCapable": True}],
     "graphPermissions": [],
     "usage": {"analyzed": True, "windowDays": 90, "totalOperations": 1203, "distinctOps": 3, "readOnly": True,
               "lastActivity": now, "scopesUsed": [RG_APP],
               "operations": [{"op": "Microsoft.RecoveryServices/vaults/read", "count": 900, "lastUsed": now, "scopes": [RG_APP]},
                              {"op": "Microsoft.Compute/virtualMachines/read", "count": 303, "lastUsed": now, "scopes": [RG_APP]}]},
     "recommendations": ["Only READ operations observed in 90 days, but a write-capable role is granted. Downgrade to Reader."],
     "remediation": ['az role assignment create --assignee <appId> --role "Reader" --scope "' + RG_APP + '"',
                     'az role assignment delete --assignee <appId> --role "Backup Contributor" --scope "' + RG_APP + '"']},
    {"id": spid["vm-prod-mi"], "appId": next(n["data"]["appId"] for n in nodes if n["id"] == spid["vm-prod-mi"]),
     "displayName": "vm-prod-mi", "type": "ManagedIdentity", "enabled": True,
     "verdict": "Justified", "overprivilege": 40,
     "grantedRoles": [{"role": "Contributor", "scope": RG_APP, "scopeLevel": "ResourceGroup", "exercised": True, "writeCapable": True}],
     "graphPermissions": [],
     "usage": {"analyzed": True, "windowDays": 90, "totalOperations": 88, "distinctOps": 6, "readOnly": False,
               "lastActivity": now, "scopesUsed": [RG_APP], "operations": []},
     "recommendations": [], "remediation": []},
]

sevcount = lambda s: sum(1 for f in findings if f["severity"] == s)
risk = min(100, sevcount("Critical")*20 + sevcount("High")*8 + sevcount("Medium")*3 + sevcount("Low")*1)
bundle = {
    "meta": {"tool": "AzIAM Assessor", "version": "1.0.0", "generatedAt": now, "tenantId": TENANT,
             "account": "you@contoso.com", "riskScore": risk,
             "subscriptions": [{"id": SUBID.split("/")[-1], "name": "prod-subscription"}]},
    "stats": {"subscriptions": 1, "users": len(users), "groups": len(groups),
              "servicePrincipals": sum(1 for s in sps if s[1] != "ManagedIdentity"),
              "managedIdentities": sum(1 for s in sps if s[1] == "ManagedIdentity"),
              "roleAssignments": len(role_assignments), "resources": len(resources),
              "findings": len(findings), "critical": sevcount("Critical"), "high": sevcount("High"),
              "medium": sevcount("Medium"), "low": sevcount("Low"), "attackPaths": len(paths),
              "tier0Nodes": sum(1 for n in nodes if n["tier0"]),
              "overPrivilegedSPs": sum(1 for r in sp_right_sizing if r["verdict"] != "Justified")},
    "findings": findings, "identities": identities, "roleAssignments": role_assignments,
    "resources": resources, "directoryRoles": dir_roles,
    "graph": {"nodes": nodes, "edges": edges}, "attackPaths": paths,
    "spRightSizing": sp_right_sizing,
}

out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "dashboard", "data.js")
with open(out, "w") as f:
    f.write("window.ASSESSMENT_DATA = " + json.dumps(bundle, indent=1) + ";\n")
print("wrote", os.path.abspath(out), "-", len(findings), "findings,", len(nodes), "nodes,", len(paths), "paths")
