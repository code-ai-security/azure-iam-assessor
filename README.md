# AzIAM Assessor

AzureHound-style **defensive** IAM assessment for your own Azure / Entra ID tenant.
It enumerates identities, Azure RBAC role assignments, Entra directory roles and
resources via the **Azure CLI**, derives misconfiguration **findings** and a
control-graph of **attack paths**, and renders an interactive **HTML GUI** with
downloadable reports.

> Authorized use only — run against tenants you own or are permitted to assess.

## Requirements (Windows)

- **PowerShell 7+** — `winget install --id Microsoft.PowerShell -e`
- **Azure CLI** — `winget install -e --id Microsoft.AzureCLI`
- A signed-in session: `az login`

Reading Entra (users, groups, SPs, directory roles) uses Microsoft Graph via
`az rest`. Your account needs at least **Directory Readers** / **Global Reader**
for full coverage. No special rights? run with `-SkipGraph` for ARM/RBAC only.

## Run

```powershell
az login
pwsh .\Invoke-Assessment.ps1                      # all subscriptions, opens dashboard
pwsh .\Invoke-Assessment.ps1 -SubscriptionId Prod # scope to one sub
pwsh .\Invoke-Assessment.ps1 -SkipGraph           # ARM-only (no Entra reads)
pwsh .\Invoke-Assessment.ps1 -OutputPath C:\reports\az -NoLaunch
```

Output lands in `.\output\`: `index.html` + `app.js` + `styles.css` + `data.js`
(the dashboard) and `assessment.json` (raw bundle). Open `output\index.html`
anytime; click **⬇ Download HTML Report** for a single self-contained file to share.

## Dashboard tabs

| Tab | What it shows |
|-----|---------------|
| Overview | Risk score, stat tiles, severity breakdown, top risks |
| Findings | Filterable misconfigurations with evidence + remediation |
| Attack Paths | Multi-hop control chains that reach Tier-0 assets |
| Network Graph | Interactive identity/resource graph (Cytoscape) |
| Identities | Users, groups, SPs, managed identities |
| Role Assignments | Every Azure RBAC assignment, privileged ones flagged |
| Directory Roles | Entra admin roles and their members |
| Resources | Inventory of resources in scope |

## What it flags

- Tier-0 Entra roles (Global Admin, Privileged Role Admin, App Admin, …)
- Owner / User Access Administrator / Contributor at subscription or MG scope
- Service principals holding privileged roles (credential-theft blast radius)
- Guest/external users with Azure RBAC
- Custom roles with wildcard / `Microsoft.Authorization/*/write` actions
- App-registration ownership → credential-add takeover paths
- Expired/stale SP secrets
- Excessive standing Global Admins

## Layout

```
Invoke-Assessment.ps1   entry point (collect -> analyze -> render)
src/AzIAM.psm1          collection + analysis engine
src/gen_sample.py       regenerate the demo dataset (no Azure needed)
dashboard/              GUI (index.html, app.js, styles.css, data.js)
output/                 generated assessment (created on run)
```

## Demo without Azure

`python3 src/gen_sample.py` writes a sample `dashboard/data.js`; open
`dashboard/index.html`. (The live run overwrites `output/data.js` with real data.)

## Notes

- Collection is **read-only** — only `az ... list/show` and Graph GET calls.
- The Network Graph tab loads Cytoscape from a CDN (needs internet once); every
  other tab and the downloaded report are fully offline/self-contained.
