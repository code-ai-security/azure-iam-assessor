window.ASSESSMENT_DATA = {
 "meta": {
  "tool": "AzIAM Assessor",
  "version": "1.0.0",
  "generatedAt": "2026-11-14T16:21:40Z",
  "tenantId": "11111111-2222-3333-4444-555555555555",
  "account": "you@contoso.com",
  "riskScore": 80,
  "subscriptions": [
   {
    "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "name": "prod-subscription"
   }
  ]
 },
 "stats": {
  "subscriptions": 1,
  "users": 7,
  "groups": 3,
  "servicePrincipals": 3,
  "managedIdentities": 2,
  "roleAssignments": 7,
  "resources": 5,
  "findings": 7,
  "critical": 3,
  "high": 2,
  "medium": 1,
  "low": 1,
  "attackPaths": 3,
  "tier0Nodes": 3,
  "overPrivilegedSPs": 3
 },
 "findings": [
  {
   "id": "dfa5f732155d",
   "severity": "Critical",
   "category": "Privileged Access",
   "title": "Tier-0 Entra role: Global Administrator",
   "description": "Identity holds the highly privileged Entra ID role 'Global Administrator', granting broad control over the directory.",
   "principal": "Alice Admin",
   "principalType": "User",
   "evidence": "Directory role 'Global Administrator'",
   "recommendation": "Enforce PIM just-in-time activation, require phishing-resistant MFA, minimize standing Global Admins (<5).",
   "references": [
    "https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure"
   ]
  },
  {
   "id": "cfcffeea96ad",
   "severity": "Critical",
   "category": "Privilege Escalation",
   "title": "User Access Administrator at Subscription scope",
   "description": "'legacy-app' holds 'User Access Administrator' at a Subscription scope, allowing it to assign roles (including to itself). Assigned to a service principal \u2014 credential theft directly yields this privilege.",
   "principal": "legacy-app",
   "principalType": "ServicePrincipal",
   "evidence": "User Access Administrator @ /subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "recommendation": "Apply least privilege; use PIM for eligible assignment; review Owner/UAA holders quarterly.",
   "references": [
    "https://learn.microsoft.com/azure/role-based-access-control/best-practices"
   ]
  },
  {
   "id": "fdfd70d62b38",
   "severity": "Critical",
   "category": "Attack Path",
   "title": "Attack path to Tier-0: Dan DevOps -> prod-subscription",
   "description": "A multi-step control path reaches a tier-0 asset: Dan DevOps -> [app owner (add credential)] legacy-app -> [can grant roles] prod-subscription",
   "principal": "Dan DevOps",
   "principalType": "Identity",
   "evidence": "Dan DevOps -> legacy-app -> prod-subscription",
   "recommendation": "Break the chain: remove app ownership or the broad UAA role along this path.",
   "references": [
    "https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model"
   ]
  },
  {
   "id": "acc84238f057",
   "severity": "High",
   "category": "Privilege Escalation",
   "title": "Owner at Subscription scope",
   "description": "'Cloud Admins' holds 'Owner' at a Subscription scope, allowing full control and role assignment.",
   "principal": "Cloud Admins",
   "principalType": "Group",
   "evidence": "Owner @ /subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "recommendation": "Convert to PIM-eligible; audit group membership (currently includes Bob, Dan).",
   "references": [
    "https://learn.microsoft.com/azure/role-based-access-control/best-practices"
   ]
  },
  {
   "id": "3b1b614a2e89",
   "severity": "High",
   "category": "Privileged Access",
   "title": "Contributor at Subscription scope",
   "description": "'terraform-ci' holds 'Contributor' across the entire subscription.",
   "principal": "terraform-ci",
   "principalType": "ServicePrincipal",
   "evidence": "Contributor @ /subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "recommendation": "Scope Contributor to specific resource groups instead of the whole subscription.",
   "references": [
    "https://learn.microsoft.com/azure/role-based-access-control/best-practices"
   ]
  },
  {
   "id": "886bb9853907",
   "severity": "Medium",
   "category": "External Access",
   "title": "Guest user holds Azure RBAC role",
   "description": "Guest (external) user 'Carol Contractor' has 'Contributor' on rg-app.",
   "principal": "Carol Contractor",
   "principalType": "Guest",
   "evidence": "Contributor @ rg-app",
   "recommendation": "Review B2B guest access; restrict guest role assignments; use access reviews.",
   "references": [
    "https://learn.microsoft.com/entra/identity/users/users-restrict-guest-permissions"
   ]
  },
  {
   "id": "5e1a6188cfc4",
   "severity": "Low",
   "category": "Credential Hygiene",
   "title": "Service principal has expired secrets: legacy-app",
   "description": "App/SP 'legacy-app' has 2 expired client secret(s) still present.",
   "principal": "legacy-app",
   "principalType": "ServicePrincipal",
   "evidence": "2 expired secrets",
   "recommendation": "Remove unused credentials; prefer workload identity federation.",
   "references": [
    "https://learn.microsoft.com/entra/workload-id/workload-identity-federation"
   ]
  }
 ],
 "identities": [
  {
   "id": "102d4cc2416c",
   "label": "Alice Admin",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "alice@contoso.com",
    "enabled": true,
    "userType": "Member"
   }
  },
  {
   "id": "70dfec6cafc5",
   "label": "Bob Builder",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "bob@contoso.com",
    "enabled": true,
    "userType": "Member"
   }
  },
  {
   "id": "b9b9224960b6",
   "label": "Carol Contractor",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "carol@partner.com",
    "enabled": true,
    "userType": "Guest"
   }
  },
  {
   "id": "ca167083aee9",
   "label": "Dan DevOps",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "dan@contoso.com",
    "enabled": true,
    "userType": "Member"
   }
  },
  {
   "id": "9f02edfb9cf9",
   "label": "Eve External",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "eve@outside.com",
    "enabled": true,
    "userType": "Guest"
   }
  },
  {
   "id": "535ab3865e60",
   "label": "Frank Finance",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "frank@contoso.com",
    "enabled": true,
    "userType": "Member"
   }
  },
  {
   "id": "ae746da02d6a",
   "label": "Svc Legacy",
   "type": "User",
   "tier0": false,
   "data": {
    "upn": "svc-legacy@contoso.com",
    "enabled": false,
    "userType": "Member"
   }
  },
  {
   "id": "bf3fb72eeaa4",
   "label": "Cloud Admins",
   "type": "Group",
   "tier0": false,
   "data": {
    "securityEnabled": true
   }
  },
  {
   "id": "a2307b7b9062",
   "label": "Developers",
   "type": "Group",
   "tier0": false,
   "data": {
    "securityEnabled": true
   }
  },
  {
   "id": "0e92c9b6f48c",
   "label": "Finance",
   "type": "Group",
   "tier0": false,
   "data": {
    "securityEnabled": true
   }
  },
  {
   "id": "1a0730eed157",
   "label": "terraform-ci",
   "type": "ServicePrincipal",
   "tier0": false,
   "data": {
    "spType": "ServicePrincipal",
    "enabled": true,
    "passwordCreds": 2,
    "keyCreds": 1,
    "appId": "ccf22bcf21cf"
   }
  },
  {
   "id": "248f3cedd95e",
   "label": "backup-runner",
   "type": "ServicePrincipal",
   "tier0": false,
   "data": {
    "spType": "ServicePrincipal",
    "enabled": true,
    "passwordCreds": 0,
    "keyCreds": 1,
    "appId": "d9b99d976334"
   }
  },
  {
   "id": "c5b6d9ccd2cc",
   "label": "legacy-app",
   "type": "ServicePrincipal",
   "tier0": false,
   "data": {
    "spType": "ServicePrincipal",
    "enabled": true,
    "passwordCreds": 3,
    "keyCreds": 0,
    "appId": "924976113a23"
   }
  },
  {
   "id": "68b6f3889cab",
   "label": "vm-prod-mi",
   "type": "ManagedIdentity",
   "tier0": false,
   "data": {
    "spType": "ManagedIdentity",
    "enabled": true,
    "passwordCreds": 0,
    "keyCreds": 0,
    "appId": "79222bd81d57"
   }
  },
  {
   "id": "b8505399acd4",
   "label": "aks-kubelet-mi",
   "type": "ManagedIdentity",
   "tier0": false,
   "data": {
    "spType": "ManagedIdentity",
    "enabled": true,
    "passwordCreds": 0,
    "keyCreds": 0,
    "appId": "ea6091264b77"
   }
  }
 ],
 "roleAssignments": [
  {
   "principalName": "Cloud Admins",
   "principalType": "Group",
   "principalId": "bf3fb72eeaa4",
   "role": "Owner",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "terraform-ci",
   "principalType": "ServicePrincipal",
   "principalId": "1a0730eed157",
   "role": "Contributor",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "legacy-app",
   "principalType": "ServicePrincipal",
   "principalId": "c5b6d9ccd2cc",
   "role": "User Access Administrator",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "Carol Contractor",
   "principalType": "User",
   "principalId": "b9b9224960b6",
   "role": "Contributor",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "Frank Finance",
   "principalType": "User",
   "principalId": "535ab3865e60",
   "role": "Reader",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "vm-prod-mi",
   "principalType": "ManagedIdentity",
   "principalId": "68b6f3889cab",
   "role": "Contributor",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "principalName": "backup-runner",
   "principalType": "ServicePrincipal",
   "principalId": "248f3cedd95e",
   "role": "Backup Contributor",
   "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }
 ],
 "resources": [
  {
   "name": "vm-prod-01",
   "type": "Microsoft.Compute/virtualMachines",
   "resourceGroup": "rg-app",
   "location": "eastus",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "name": "kv-prod-secrets",
   "type": "Microsoft.KeyVault/vaults",
   "resourceGroup": "rg-app",
   "location": "eastus",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "name": "stproddata001",
   "type": "Microsoft.Storage/storageAccounts",
   "resourceGroup": "rg-app",
   "location": "eastus",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "name": "aks-prod",
   "type": "Microsoft.ContainerService/managedClusters",
   "resourceGroup": "rg-infra",
   "location": "eastus",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  },
  {
   "name": "sql-finance",
   "type": "Microsoft.Sql/servers",
   "resourceGroup": "rg-fin",
   "location": "eastus",
   "subscription": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }
 ],
 "directoryRoles": [
  {
   "roleName": "Global Administrator",
   "memberCount": 1,
   "members": [
    "Alice Admin"
   ]
  },
  {
   "roleName": "Application Administrator",
   "memberCount": 1,
   "members": [
    "Dan DevOps"
   ]
  },
  {
   "roleName": "Security Reader",
   "memberCount": 0,
   "members": []
  }
 ],
 "graph": {
  "nodes": [
   {
    "id": "102d4cc2416c",
    "label": "Alice Admin",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "alice@contoso.com",
     "enabled": true,
     "userType": "Member"
    }
   },
   {
    "id": "70dfec6cafc5",
    "label": "Bob Builder",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "bob@contoso.com",
     "enabled": true,
     "userType": "Member"
    }
   },
   {
    "id": "b9b9224960b6",
    "label": "Carol Contractor",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "carol@partner.com",
     "enabled": true,
     "userType": "Guest"
    }
   },
   {
    "id": "ca167083aee9",
    "label": "Dan DevOps",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "dan@contoso.com",
     "enabled": true,
     "userType": "Member"
    }
   },
   {
    "id": "9f02edfb9cf9",
    "label": "Eve External",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "eve@outside.com",
     "enabled": true,
     "userType": "Guest"
    }
   },
   {
    "id": "535ab3865e60",
    "label": "Frank Finance",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "frank@contoso.com",
     "enabled": true,
     "userType": "Member"
    }
   },
   {
    "id": "ae746da02d6a",
    "label": "Svc Legacy",
    "type": "User",
    "tier0": false,
    "data": {
     "upn": "svc-legacy@contoso.com",
     "enabled": false,
     "userType": "Member"
    }
   },
   {
    "id": "bf3fb72eeaa4",
    "label": "Cloud Admins",
    "type": "Group",
    "tier0": false,
    "data": {
     "securityEnabled": true
    }
   },
   {
    "id": "a2307b7b9062",
    "label": "Developers",
    "type": "Group",
    "tier0": false,
    "data": {
     "securityEnabled": true
    }
   },
   {
    "id": "0e92c9b6f48c",
    "label": "Finance",
    "type": "Group",
    "tier0": false,
    "data": {
     "securityEnabled": true
    }
   },
   {
    "id": "1a0730eed157",
    "label": "terraform-ci",
    "type": "ServicePrincipal",
    "tier0": false,
    "data": {
     "spType": "ServicePrincipal",
     "enabled": true,
     "passwordCreds": 2,
     "keyCreds": 1,
     "appId": "ccf22bcf21cf"
    }
   },
   {
    "id": "248f3cedd95e",
    "label": "backup-runner",
    "type": "ServicePrincipal",
    "tier0": false,
    "data": {
     "spType": "ServicePrincipal",
     "enabled": true,
     "passwordCreds": 0,
     "keyCreds": 1,
     "appId": "d9b99d976334"
    }
   },
   {
    "id": "c5b6d9ccd2cc",
    "label": "legacy-app",
    "type": "ServicePrincipal",
    "tier0": false,
    "data": {
     "spType": "ServicePrincipal",
     "enabled": true,
     "passwordCreds": 3,
     "keyCreds": 0,
     "appId": "924976113a23"
    }
   },
   {
    "id": "68b6f3889cab",
    "label": "vm-prod-mi",
    "type": "ManagedIdentity",
    "tier0": false,
    "data": {
     "spType": "ManagedIdentity",
     "enabled": true,
     "passwordCreds": 0,
     "keyCreds": 0,
     "appId": "79222bd81d57"
    }
   },
   {
    "id": "b8505399acd4",
    "label": "aks-kubelet-mi",
    "type": "ManagedIdentity",
    "tier0": false,
    "data": {
     "spType": "ManagedIdentity",
     "enabled": true,
     "passwordCreds": 0,
     "keyCreds": 0,
     "appId": "ea6091264b77"
    }
   },
   {
    "id": "dirrole:Global Administrator",
    "label": "Global Administrator",
    "type": "DirectoryRole",
    "tier0": true,
    "data": {}
   },
   {
    "id": "dirrole:Application Administrator",
    "label": "Application Administrator",
    "type": "DirectoryRole",
    "tier0": true,
    "data": {}
   },
   {
    "id": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "label": "prod-subscription",
    "type": "Subscription",
    "tier0": true,
    "data": {
     "fullScope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    }
   },
   {
    "id": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
    "label": "rg-app",
    "type": "ResourceGroup",
    "tier0": false,
    "data": {
     "fullScope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
    }
   }
  ],
  "edges": [
   {
    "id": "102d4cc2416c->dirrole:Global Administrator->HasDirectoryRole",
    "source": "102d4cc2416c",
    "target": "dirrole:Global Administrator",
    "type": "HasDirectoryRole",
    "label": "Global Administrator"
   },
   {
    "id": "ca167083aee9->dirrole:Application Administrator->HasDirectoryRole",
    "source": "ca167083aee9",
    "target": "dirrole:Application Administrator",
    "type": "HasDirectoryRole",
    "label": "Application Administrator"
   },
   {
    "id": "70dfec6cafc5->bf3fb72eeaa4->MemberOf",
    "source": "70dfec6cafc5",
    "target": "bf3fb72eeaa4",
    "type": "MemberOf",
    "label": "member of"
   },
   {
    "id": "ca167083aee9->bf3fb72eeaa4->MemberOf",
    "source": "ca167083aee9",
    "target": "bf3fb72eeaa4",
    "type": "MemberOf",
    "label": "member of"
   },
   {
    "id": "535ab3865e60->0e92c9b6f48c->MemberOf",
    "source": "535ab3865e60",
    "target": "0e92c9b6f48c",
    "type": "MemberOf",
    "label": "member of"
   },
   {
    "id": "bf3fb72eeaa4->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->HasRole",
    "source": "bf3fb72eeaa4",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "HasRole",
    "label": "Owner"
   },
   {
    "id": "bf3fb72eeaa4->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->CanEscalate",
    "source": "bf3fb72eeaa4",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "CanEscalate",
    "label": "can grant roles"
   },
   {
    "id": "1a0730eed157->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->HasRole",
    "source": "1a0730eed157",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "HasRole",
    "label": "Contributor"
   },
   {
    "id": "c5b6d9ccd2cc->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->HasRole",
    "source": "c5b6d9ccd2cc",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "HasRole",
    "label": "User Access Administrator"
   },
   {
    "id": "c5b6d9ccd2cc->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->CanEscalate",
    "source": "c5b6d9ccd2cc",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "CanEscalate",
    "label": "can grant roles"
   },
   {
    "id": "b9b9224960b6->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app->HasRole",
    "source": "b9b9224960b6",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
    "type": "HasRole",
    "label": "Contributor"
   },
   {
    "id": "535ab3865e60->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee->HasRole",
    "source": "535ab3865e60",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "type": "HasRole",
    "label": "Reader"
   },
   {
    "id": "68b6f3889cab->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app->HasRole",
    "source": "68b6f3889cab",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
    "type": "HasRole",
    "label": "Contributor"
   },
   {
    "id": "248f3cedd95e->scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app->HasRole",
    "source": "248f3cedd95e",
    "target": "scope:/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
    "type": "HasRole",
    "label": "Backup Contributor"
   },
   {
    "id": "ca167083aee9->c5b6d9ccd2cc->CanControl",
    "source": "ca167083aee9",
    "target": "c5b6d9ccd2cc",
    "type": "CanControl",
    "label": "app owner (add credential)"
   }
  ]
 },
 "attackPaths": [
  {
   "id": "690a0248",
   "title": "Dan DevOps -> prod-subscription",
   "start": "Dan DevOps",
   "target": "prod-subscription",
   "severity": "Critical",
   "length": 2,
   "steps": [
    "Dan DevOps",
    "[app owner (add credential)] legacy-app",
    "[can grant roles] prod-subscription"
   ]
  },
  {
   "id": "44a4c431",
   "title": "Bob Builder -> prod-subscription",
   "start": "Bob Builder",
   "target": "prod-subscription",
   "severity": "Critical",
   "length": 2,
   "steps": [
    "Bob Builder",
    "[member of] Cloud Admins",
    "[can grant roles] prod-subscription"
   ]
  },
  {
   "id": "68922cc5",
   "title": "Alice Admin -> Global Administrator",
   "start": "Alice Admin",
   "target": "Global Administrator",
   "severity": "High",
   "length": 1,
   "steps": [
    "Alice Admin",
    "[Global Administrator] Global Administrator"
   ]
  }
 ],
 "spRightSizing": [
  {
   "id": "c5b6d9ccd2cc",
   "appId": "924976113a23",
   "displayName": "legacy-app",
   "type": "ServicePrincipal",
   "enabled": true,
   "verdict": "ReviewGraph",
   "overprivilege": 96,
   "grantedRoles": [
    {
     "role": "User Access Administrator",
     "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
     "scopeLevel": "Subscription",
     "exercised": false,
     "writeCapable": true
    }
   ],
   "graphPermissions": [
    {
     "permission": "Directory.ReadWrite.All",
     "api": "Microsoft Graph",
     "highRisk": true
    },
    {
     "permission": "Application.ReadWrite.All",
     "api": "Microsoft Graph",
     "highRisk": true
    },
    {
     "permission": "User.Read.All",
     "api": "Microsoft Graph",
     "highRisk": false
    }
   ],
   "usage": {
    "analyzed": true,
    "windowDays": 90,
    "totalOperations": 0,
    "distinctOps": 0,
    "readOnly": false,
    "lastActivity": null,
    "scopesUsed": [],
    "operations": []
   },
   "recommendations": [
    "No control-plane activity in the last 90 days. Candidate to remove RBAC or disable the SP.",
    "Holds high-risk Graph application permission(s): Directory.ReadWrite.All, Application.ReadWrite.All. These bypass RBAC entirely \u2014 remove any not required."
   ],
   "remediation": [
    "az role assignment delete --assignee <appId> --role \"User Access Administrator\" --scope \"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\"",
    "# Review/remove Graph app permission 'Directory.ReadWrite.All' in Entra > App registrations > legacy-app > API permissions"
   ]
  },
  {
   "id": "1a0730eed157",
   "appId": "ccf22bcf21cf",
   "displayName": "terraform-ci",
   "type": "ServicePrincipal",
   "enabled": true,
   "verdict": "ScopeReduction",
   "overprivilege": 75,
   "grantedRoles": [
    {
     "role": "Contributor",
     "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
     "scopeLevel": "Subscription",
     "exercised": true,
     "writeCapable": true
    }
   ],
   "graphPermissions": [],
   "usage": {
    "analyzed": true,
    "windowDays": 90,
    "totalOperations": 412,
    "distinctOps": 9,
    "readOnly": false,
    "lastActivity": "2026-11-14T16:21:40Z",
    "scopesUsed": [
     "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
    ],
    "operations": [
     {
      "op": "Microsoft.Resources/deployments/write",
      "count": 180,
      "lastUsed": "2026-11-14T16:21:40Z",
      "scopes": [
       "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
      ]
     },
     {
      "op": "Microsoft.Storage/storageAccounts/write",
      "count": 44,
      "lastUsed": "2026-11-14T16:21:40Z",
      "scopes": [
       "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
      ]
     }
    ]
   },
   "recommendations": [
    "Activity is confined to 1 resource group (rg-app) but the role is granted subscription-wide. Re-scope to just that RG."
   ],
   "remediation": [
    "az role assignment create --assignee <appId> --role \"Contributor\" --scope \"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app\"",
    "az role assignment delete --assignee <appId> --role \"Contributor\" --scope \"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\""
   ]
  },
  {
   "id": "248f3cedd95e",
   "appId": "d9b99d976334",
   "displayName": "backup-runner",
   "type": "ServicePrincipal",
   "enabled": true,
   "verdict": "ReadOnly",
   "overprivilege": 85,
   "grantedRoles": [
    {
     "role": "Backup Contributor",
     "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
     "scopeLevel": "ResourceGroup",
     "exercised": true,
     "writeCapable": true
    }
   ],
   "graphPermissions": [],
   "usage": {
    "analyzed": true,
    "windowDays": 90,
    "totalOperations": 1203,
    "distinctOps": 3,
    "readOnly": true,
    "lastActivity": "2026-11-14T16:21:40Z",
    "scopesUsed": [
     "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
    ],
    "operations": [
     {
      "op": "Microsoft.RecoveryServices/vaults/read",
      "count": 900,
      "lastUsed": "2026-11-14T16:21:40Z",
      "scopes": [
       "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
      ]
     },
     {
      "op": "Microsoft.Compute/virtualMachines/read",
      "count": 303,
      "lastUsed": "2026-11-14T16:21:40Z",
      "scopes": [
       "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
      ]
     }
    ]
   },
   "recommendations": [
    "Only READ operations observed in 90 days, but a write-capable role is granted. Downgrade to Reader."
   ],
   "remediation": [
    "az role assignment create --assignee <appId> --role \"Reader\" --scope \"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app\"",
    "az role assignment delete --assignee <appId> --role \"Backup Contributor\" --scope \"/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app\""
   ]
  },
  {
   "id": "68b6f3889cab",
   "appId": "79222bd81d57",
   "displayName": "vm-prod-mi",
   "type": "ManagedIdentity",
   "enabled": true,
   "verdict": "Justified",
   "overprivilege": 40,
   "grantedRoles": [
    {
     "role": "Contributor",
     "scope": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app",
     "scopeLevel": "ResourceGroup",
     "exercised": true,
     "writeCapable": true
    }
   ],
   "graphPermissions": [],
   "usage": {
    "analyzed": true,
    "windowDays": 90,
    "totalOperations": 88,
    "distinctOps": 6,
    "readOnly": false,
    "lastActivity": "2026-11-14T16:21:40Z",
    "scopesUsed": [
     "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/rg-app"
    ],
    "operations": []
   },
   "recommendations": [],
   "remediation": []
  }
 ]
};
