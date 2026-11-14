<#
    AzIAM.psm1  -  Azure IAM Assessment Engine
    ------------------------------------------------
    Defensive security tooling for assessing YOUR OWN Azure / Entra ID tenant.
    Collects identities, role assignments and resources via the Azure CLI,
    then derives misconfiguration findings, control relationships and attack
    paths (BloodHound/AzureHound-style) for review.

    Requires: PowerShell 7+ (pwsh), Azure CLI (az) with an authenticated session.
#>

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$script:ToolVersion = '1.0.0'

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

function Write-Step {
    param([string]$Message, [string]$Status = 'INFO')
    $color = switch ($Status) {
        'OK'   { 'Green' }
        'WARN' { 'Yellow' }
        'ERR'  { 'Red' }
        default { 'Cyan' }
    }
    Write-Host ("[{0}] {1}" -f $Status.PadRight(4), $Message) -ForegroundColor $color
}

function Invoke-Az {
    <# Runs an 'az' command, returns parsed JSON (or $null on failure). Never throws. #>
    param(
        [Parameter(Mandatory)][string[]]$Args,
        [switch]$Raw
    )
    try {
        $out = & az @Args -o json 2>$null
        if (-not $out) { return $null }
        if ($Raw) { return $out }
        return ($out | ConvertFrom-Json -Depth 50)
    } catch {
        Write-Step "az $($Args -join ' ') failed: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Invoke-Graph {
    <# Calls Microsoft Graph via 'az rest'. Returns .value array (handles paging). #>
    param([Parameter(Mandatory)][string]$Url)
    $items = @()
    $next = $Url
    try {
        while ($next) {
            $resp = & az rest --method GET --url $next --headers "ConsistencyLevel=eventual" -o json 2>$null | ConvertFrom-Json -Depth 50
            if ($null -eq $resp) { break }
            if ($resp.value) { $items += $resp.value } elseif ($resp.id) { $items += $resp }
            $next = $resp.'@odata.nextLink'
        }
    } catch {
        Write-Step "Graph call failed ($Url): $($_.Exception.Message)" 'WARN'
    }
    return $items
}

function Test-AzLogin {
    $acct = Invoke-Az -Args @('account', 'show')
    if (-not $acct) {
        throw "Not logged in to Azure CLI. Run 'az login' first."
    }
    return $acct
}

# ----------------------------------------------------------------------------
# Collection
# ----------------------------------------------------------------------------

function Invoke-AzCollection {
    <#
      .SYNOPSIS  Collect raw IAM-relevant data from the current Azure tenant.
      .OUTPUTS   Hashtable of raw collections.
    #>
    param(
        [string[]]$SubscriptionId,
        [switch]$SkipGraph,
        [switch]$AnalyzeUsage,
        [int]$UsageDays = 90
    )

    $account = Test-AzLogin
    Write-Step "Tenant: $($account.tenantId)  Account: $($account.user.name)" 'OK'

    # --- Subscriptions ---
    $subs = Invoke-Az -Args @('account', 'list', '--all')
    if ($SubscriptionId) { $subs = $subs | Where-Object { $_.id -in $SubscriptionId -or $_.name -in $SubscriptionId } }
    if (-not $subs) { $subs = @($account) }
    Write-Step "Subscriptions in scope: $($subs.Count)" 'INFO'

    $raw = @{
        account         = $account
        subscriptions   = $subs
        roleAssignments = @()
        roleDefinitions = @()
        resources       = @()
        users           = @()
        groups          = @()
        groupMembers    = @{}
        servicePrincipals = @()
        applications    = @()
        appOwners       = @{}
        directoryRoles  = @()
        managedIdentities = @()
        spAppRoles      = @{}   # spObjectId -> [ {resourceId, appRoleId, resourceName} ]  (granted Graph app permissions)
        graphAppRoleMap = @{}   # resourceSpId -> { appRoleId -> value }  (translation table)
        oauthGrants     = @{}   # spObjectId -> [ {resourceId, scope} ]  (delegated grants)
        spActivity      = @{}   # spObjectId -> [ {op, count, lastUsed, scopes[]} ]  (from Activity Log)
        usageDays       = $UsageDays
        usageAnalyzed   = [bool]$AnalyzeUsage
        collectedAt     = (Get-Date).ToUniversalTime().ToString('o')
    }

    # --- Per-subscription Azure RBAC + resources ---
    foreach ($sub in $subs) {
        Write-Step "Collecting subscription '$($sub.name)' ($($sub.id))" 'INFO'
        & az account set --subscription $sub.id 2>$null

        $ra = Invoke-Az -Args @('role', 'assignment', 'list', '--all', '--include-inherited', '--include-groups')
        if ($ra) {
            foreach ($r in $ra) { $r | Add-Member -NotePropertyName _subscriptionId -NotePropertyValue $sub.id -Force }
            $raw.roleAssignments += $ra
        }

        $rd = Invoke-Az -Args @('role', 'definition', 'list')
        if ($rd) { $raw.roleDefinitions += $rd }

        $res = Invoke-Az -Args @('resource', 'list')
        if ($res) {
            foreach ($r in $res) { $r | Add-Member -NotePropertyName _subscriptionId -NotePropertyValue $sub.id -Force }
            $raw.resources += $res
        }
    }

    # Dedupe role definitions by id
    $raw.roleDefinitions = $raw.roleDefinitions | Sort-Object -Property name -Unique

    # --- Entra ID (Graph) directory objects ---
    if (-not $SkipGraph) {
        Write-Step "Collecting Entra ID directory objects via Microsoft Graph" 'INFO'

        $raw.users = Invoke-Graph 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&$top=999'
        $raw.groups = Invoke-Graph 'https://graph.microsoft.com/v1.0/groups?$select=id,displayName,securityEnabled,groupTypes,onPremisesSyncEnabled&$top=999'
        $raw.servicePrincipals = Invoke-Graph 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appRoleAssignmentRequired,keyCredentials,passwordCredentials&$top=999'
        $raw.applications = Invoke-Graph 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,keyCredentials,passwordCredentials&$top=999'

        # Directory role memberships (Global Admin, etc.)
        $dirRoles = Invoke-Graph 'https://graph.microsoft.com/v1.0/directoryRoles'
        foreach ($dr in $dirRoles) {
            $members = Invoke-Graph "https://graph.microsoft.com/v1.0/directoryRoles/$($dr.id)/members?`$select=id,displayName,userPrincipalName"
            $raw.directoryRoles += [pscustomobject]@{
                roleId      = $dr.id
                roleName    = $dr.displayName
                templateId  = $dr.roleTemplateId
                members     = $members
            }
        }

        # Group membership (best effort, limited to groups that hold role assignments)
        $assignedGroupIds = $raw.roleAssignments | Where-Object { $_.principalType -eq 'Group' } |
            Select-Object -ExpandProperty principalId -Unique
        foreach ($gid in $assignedGroupIds) {
            if (-not $gid) { continue }
            $m = Invoke-Graph "https://graph.microsoft.com/v1.0/groups/$gid/members?`$select=id,displayName,userPrincipalName"
            $raw.groupMembers[$gid] = $m
        }

        # App owners (app registration takeover paths)
        foreach ($app in $raw.applications) {
            $owners = Invoke-Graph "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
            if ($owners) { $raw.appOwners[$app.appId] = $owners }
        }

        # Managed identities are service principals of type ManagedIdentity
        $raw.managedIdentities = $raw.servicePrincipals | Where-Object { $_.servicePrincipalType -eq 'ManagedIdentity' }

        # --- Graph application permissions (the Entra consent blind spot) ---
        # Only for SPs that actually hold Azure RBAC or are non-MI apps, to bound cost.
        $rbacPrincipalIds = @($raw.roleAssignments | Where-Object { $_.principalType -in @('ServicePrincipal') } |
            Select-Object -ExpandProperty principalId -Unique)
        $spToInspect = $raw.servicePrincipals | Where-Object {
            $_.servicePrincipalType -ne 'ManagedIdentity' -and ($_.id -in $rbacPrincipalIds -or $true)
        }
        foreach ($sp in $spToInspect) {
            $assignments = Invoke-Graph "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments?`$top=999"
            if ($assignments) {
                $raw.spAppRoles[$sp.id] = @($assignments | ForEach-Object {
                    @{ resourceId = $_.resourceId; appRoleId = $_.appRoleId; resourceName = $_.resourceDisplayName }
                })
                # Build translation tables for each distinct resource SP (e.g. Microsoft Graph)
                foreach ($resId in ($assignments.resourceId | Select-Object -Unique)) {
                    if (-not $raw.graphAppRoleMap.ContainsKey($resId)) {
                        $resSp = Invoke-Graph "https://graph.microsoft.com/v1.0/servicePrincipals/$resId`?`$select=appRoles,displayName"
                        $map = @{}
                        foreach ($ar in @($resSp.appRoles)) { if ($ar.id) { $map[$ar.id] = $ar.value } }
                        $raw.graphAppRoleMap[$resId] = $map
                    }
                }
            }
            $grants = Invoke-Graph "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/oauth2PermissionGrants"
            if ($grants) { $raw.oauthGrants[$sp.id] = @($grants | ForEach-Object { @{ resourceId = $_.resourceId; scope = $_.scope } }) }
        }
        Write-Step "Entra: $($raw.users.Count) users, $($raw.groups.Count) groups, $($raw.servicePrincipals.Count) SPs, $($raw.directoryRoles.Count) directory roles, Graph perms on $($raw.spAppRoles.Count) SPs" 'OK'
    } else {
        Write-Step "Skipping Microsoft Graph collection (-SkipGraph)" 'WARN'
    }

    # --- Usage from Activity Logs (what each SP ACTUALLY did) ---
    if ($AnalyzeUsage) {
        $startTime = (Get-Date).AddDays(-$UsageDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        # SPs worth right-sizing = those holding Azure RBAC (identified by principalId / appId).
        $rbacSps = $raw.servicePrincipals | Where-Object {
            $_.id -in @($raw.roleAssignments | Where-Object principalType -in @('ServicePrincipal') | Select-Object -ExpandProperty principalId)
        }
        Write-Step "Collecting $UsageDays-day Activity Log usage for $($rbacSps.Count) service principals (this can take a minute)" 'INFO'
        foreach ($sub in $subs) {
            & az account set --subscription $sub.id 2>$null
            foreach ($sp in $rbacSps) {
                # 'caller' in activity log is typically the appId for an SP.
                $events = Invoke-Az -Args @('monitor', 'activity-log', 'list',
                    '--caller', $sp.appId, '--start-time', $startTime, '--max-events', '1000',
                    '--query', "[?authorization.action!=null].{op:authorization.action, time:eventTimestamp, rid:resourceId, status:status.value}")
                if (-not $events) { continue }
                $byOp = @{}
                foreach ($e in $events) {
                    $op = $e.op
                    if (-not $op) { continue }
                    if (-not $byOp.ContainsKey($op)) { $byOp[$op] = @{ op = $op; count = 0; lastUsed = $e.time; scopes = @{} } }
                    $byOp[$op].count++
                    if ($e.time -gt $byOp[$op].lastUsed) { $byOp[$op].lastUsed = $e.time }
                    $rg = Get-RgScope $e.rid
                    if ($rg) { $byOp[$op].scopes[$rg] = $true }
                }
                if ($byOp.Count) {
                    $existing = @()
                    if ($raw.spActivity.ContainsKey($sp.id)) { $existing = $raw.spActivity[$sp.id] }
                    $raw.spActivity[$sp.id] = $existing + @($byOp.Values | ForEach-Object {
                        @{ op = $_.op; count = $_.count; lastUsed = $_.lastUsed; scopes = @($_.scopes.Keys) }
                    })
                }
            }
        }
        Write-Step "Usage collected for $($raw.spActivity.Count) active SPs" 'OK'
    }

    Write-Step "Collection complete: $($raw.roleAssignments.Count) role assignments, $($raw.resources.Count) resources" 'OK'
    return $raw
}

function Get-RgScope {
    <# Reduce a resourceId to its resource-group-level scope for 'where is this SP actually active' analysis. #>
    param([string]$ResourceId)
    if (-not $ResourceId) { return $null }
    $m = [regex]::Match($ResourceId, '^(/subscriptions/[^/]+/resourceGroups/[^/]+)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    $m2 = [regex]::Match($ResourceId, '^(/subscriptions/[^/]+)', 'IgnoreCase')
    if ($m2.Success) { return $m2.Groups[1].Value }
    return $null
}

function Get-ScopeLevel {
    param([string]$Scope)
    switch -Regex ($Scope) {
        '/managementGroups/'         { return 'ManagementGroup' }
        '^/subscriptions/[^/]+$'     { return 'Subscription' }
        '/resourceGroups/[^/]+$'     { return 'ResourceGroup' }
        '/providers/.+/.+'           { return 'Resource' }
        '^/$'                        { return 'Root' }
        default                      { return 'Other' }
    }
}

# ----------------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------------

# Roles that can assign roles / escalate privilege within an Azure scope
$script:Tier0AzureRoles = @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator')
$script:HighAzureRoles  = @('Contributor', 'Access Review Operator Service Role')
# Entra directory roles considered tier-0 (control of the directory)
$script:Tier0DirRoles   = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Hybrid Identity Administrator',
    'Partner Tier2 Support', 'Domain Name Administrator', 'Intune Administrator'
)
$script:DangerousActions = @('*', 'Microsoft.Authorization/*', 'Microsoft.Authorization/*/Write',
    'Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/elevateAccess/action')

function New-Finding {
    param(
        [string]$Severity, [string]$Category, [string]$Title, [string]$Description,
        [string]$Principal, [string]$PrincipalType, [string]$Evidence,
        [string]$Recommendation, [string[]]$References
    )
    [pscustomobject]@{
        id             = [guid]::NewGuid().ToString('N').Substring(0, 12)
        severity       = $Severity
        category       = $Category
        title          = $Title
        description    = $Description
        principal      = $Principal
        principalType  = $PrincipalType
        evidence       = $Evidence
        recommendation = $Recommendation
        references     = $References
    }
}

function Invoke-AzAnalysis {
    <#
      .SYNOPSIS  Turn raw collection into findings, a control graph and attack paths.
      .OUTPUTS   The full assessment bundle (hashtable) consumed by the dashboard.
    #>
    param([Parameter(Mandatory)][hashtable]$Raw)

    Write-Step "Analyzing collected data" 'INFO'
    $findings    = [System.Collections.Generic.List[object]]::new()
    $nodes       = @{}   # id -> node
    $edges       = [System.Collections.Generic.List[object]]::new()
    $roleDefMap  = @{}
    foreach ($rd in $Raw.roleDefinitions) { if ($rd.name) { $roleDefMap[$rd.name] = $rd } }

    # ---- node factory ----
    function Add-Node {
        param([string]$Id, [string]$Label, [string]$Type, [hashtable]$Data, [bool]$Tier0 = $false)
        if (-not $Id) { return }
        if (-not $nodes.ContainsKey($Id)) {
            $nodes[$Id] = [pscustomobject]@{ id = $Id; label = $Label; type = $Type; tier0 = $Tier0; data = $Data }
        } elseif ($Tier0) {
            $nodes[$Id].tier0 = $true
        }
    }
    function Add-Edge {
        param([string]$Source, [string]$Target, [string]$Type, [string]$Label)
        if (-not $Source -or -not $Target) { return }
        $edges.Add([pscustomobject]@{
            id = "$Source->$Target->$Type"; source = $Source; target = $Target; type = $Type; label = $Label
        })
    }

    # ---- index identities as nodes ----
    foreach ($u in $Raw.users) {
        Add-Node -Id $u.id -Label ($u.displayName ?? $u.userPrincipalName) -Type 'User' -Data @{
            upn = $u.userPrincipalName; enabled = $u.accountEnabled; userType = $u.userType
            created = $u.createdDateTime; lastSignIn = $u.signInActivity.lastSignInDateTime
        }
    }
    foreach ($g in $Raw.groups) {
        Add-Node -Id $g.id -Label $g.displayName -Type 'Group' -Data @{
            securityEnabled = $g.securityEnabled; onPremSync = $g.onPremisesSyncEnabled
        }
    }
    foreach ($sp in $Raw.servicePrincipals) {
        $t = if ($sp.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
        Add-Node -Id $sp.id -Label $sp.displayName -Type $t -Data @{
            appId = $sp.appId; spType = $sp.servicePrincipalType; enabled = $sp.accountEnabled
            keyCreds = ($sp.keyCredentials | Measure-Object).Count
            passwordCreds = ($sp.passwordCredentials | Measure-Object).Count
        }
    }

    # ---- group membership edges ----
    foreach ($gid in $Raw.groupMembers.Keys) {
        foreach ($m in $Raw.groupMembers[$gid]) {
            Add-Node -Id $m.id -Label ($m.displayName ?? $m.userPrincipalName) -Type 'User' -Data @{ upn = $m.userPrincipalName }
            Add-Edge -Source $m.id -Target $gid -Type 'MemberOf' -Label 'member of'
        }
    }

    # ---- directory role (Entra) analysis ----
    foreach ($dr in $Raw.directoryRoles) {
        $isTier0 = $script:Tier0DirRoles -contains $dr.roleName
        $roleNodeId = "dirrole:$($dr.roleName)"
        Add-Node -Id $roleNodeId -Label $dr.roleName -Type 'DirectoryRole' -Data @{ templateId = $dr.templateId } -Tier0 $isTier0
        foreach ($m in $dr.members) {
            Add-Node -Id $m.id -Label ($m.displayName ?? $m.userPrincipalName) -Type 'User' -Data @{ upn = $m.userPrincipalName }
            Add-Edge -Source $m.id -Target $roleNodeId -Type 'HasDirectoryRole' -Label $dr.roleName
            if ($isTier0) {
                $findings.Add((New-Finding -Severity 'Critical' -Category 'Privileged Access' `
                    -Title "Tier-0 Entra role: $($dr.roleName)" `
                    -Description "Identity holds the highly privileged Entra ID role '$($dr.roleName)', granting broad control over the directory." `
                    -Principal ($m.displayName ?? $m.userPrincipalName) -PrincipalType 'User' `
                    -Evidence "Directory role '$($dr.roleName)'" `
                    -Recommendation "Enforce PIM just-in-time activation, require phishing-resistant MFA, and minimize standing Global/Privileged admins (target < 5)." `
                    -References @('https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure')))
            }
        }
        $memberCount = ($dr.members | Measure-Object).Count
        if ($dr.roleName -eq 'Global Administrator' -and $memberCount -gt 5) {
            $findings.Add((New-Finding -Severity 'High' -Category 'Privileged Access' `
                -Title "Excessive Global Administrators ($memberCount)" `
                -Description "There are $memberCount standing Global Administrators. Microsoft recommends fewer than 5." `
                -Principal 'Tenant' -PrincipalType 'Tenant' -Evidence "$memberCount Global Admins" `
                -Recommendation "Reduce standing Global Admins, move to PIM eligible assignments." `
                -References @('https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices')))
        }
    }

    # ---- Azure RBAC role assignment analysis ----
    foreach ($ra in $Raw.roleAssignments) {
        $pName = $ra.principalName ?? $ra.principalId
        $pType = $ra.principalType ?? 'Unknown'
        $role  = $ra.roleDefinitionName
        $scope = $ra.scope
        $pid   = $ra.principalId
        $scopeType = switch -Regex ($scope) {
            '^/subscriptions/[^/]+$'                 { 'Subscription' }
            '/managementGroups/'                     { 'ManagementGroup' }
            '/resourceGroups/[^/]+$'                 { 'ResourceGroup' }
            '/providers/.+/.+'                       { 'Resource' }
            '^/$'                                    { 'Root' }
            default                                  { 'Other' }
        }

        Add-Node -Id $pid -Label $pName -Type $pType -Data @{ fromRbacOnly = $true }
        $scopeNode = "scope:$scope"
        Add-Node -Id $scopeNode -Label (($scope -split '/')[-1]) -Type $scopeType -Data @{ fullScope = $scope }
        Add-Edge -Source $pid -Target $scopeNode -Type 'HasRole' -Label $role

        $broadScope = $scopeType -in @('Subscription', 'ManagementGroup', 'Root')
        $isTier0Role = $script:Tier0AzureRoles -contains $role

        if ($isTier0Role) {
            $nodes[$scopeNode].tier0 = $true
            # Owner/UAA can assign roles -> models privilege-escalation control over the scope
            Add-Edge -Source $pid -Target $scopeNode -Type 'CanEscalate' -Label 'can grant roles'
            $sev = if ($broadScope) { 'Critical' } else { 'High' }
            $spWarn = if ($pType -in @('ServicePrincipal')) { ' Assigned to a service principal — credential theft directly yields this privilege.' } else { '' }
            $findings.Add((New-Finding -Severity $sev -Category 'Privilege Escalation' `
                -Title "$role at $scopeType scope" `
                -Description "'$pName' holds '$role' at a $scopeType scope, allowing it to assign roles (including to itself) and fully control resources under that scope.$spWarn" `
                -Principal $pName -PrincipalType $pType -Evidence "$role @ $scope" `
                -Recommendation "Apply least privilege; prefer narrowly-scoped built-in roles; use PIM for eligible (not permanent) assignment; review Owner/UAA holders quarterly." `
                -References @('https://learn.microsoft.com/azure/role-based-access-control/best-practices')))
        } elseif (($script:HighAzureRoles -contains $role) -and $broadScope) {
            $findings.Add((New-Finding -Severity 'High' -Category 'Privileged Access' `
                -Title "$role at $scopeType scope" `
                -Description "'$pName' holds '$role' across an entire $scopeType, a very broad grant." `
                -Principal $pName -PrincipalType $pType -Evidence "$role @ $scope" `
                -Recommendation "Scope Contributor to specific resource groups/resources instead of the whole subscription." `
                -References @('https://learn.microsoft.com/azure/role-based-access-control/best-practices')))
        }

        # Guest / external principal with any Azure role
        $node = $nodes[$pid]
        if ($pType -eq 'User' -and $node.data.userType -eq 'Guest') {
            $findings.Add((New-Finding -Severity 'Medium' -Category 'External Access' `
                -Title "Guest user holds Azure RBAC role" `
                -Description "Guest (external) user '$pName' has '$role' on $scope." `
                -Principal $pName -PrincipalType 'Guest' -Evidence "$role @ $scope" `
                -Recommendation "Review B2B guest access; restrict guest role assignments; consider Entra access reviews." `
                -References @('https://learn.microsoft.com/entra/identity/users/users-restrict-guest-permissions')))
        }
    }

    # ---- custom roles with dangerous actions ----
    foreach ($rd in $Raw.roleDefinitions) {
        if ($rd.roleType -eq 'CustomRole' -or $rd.type -eq 'CustomRole') {
            $actions = @()
            foreach ($perm in $rd.permissions) { $actions += $perm.actions }
            $danger = $actions | Where-Object { $script:DangerousActions -contains $_ }
            if ($danger) {
                $findings.Add((New-Finding -Severity 'High' -Category 'Risky Configuration' `
                    -Title "Custom role with dangerous actions: $($rd.roleName)" `
                    -Description "Custom role '$($rd.roleName)' grants wildcard / authorization-write actions: $($danger -join ', ')." `
                    -Principal $rd.roleName -PrincipalType 'Role' -Evidence ($danger -join ', ') `
                    -Recommendation "Replace wildcards with explicit actions; never grant Microsoft.Authorization/*/write in a custom role unless intended for delegation." `
                    -References @('https://learn.microsoft.com/azure/role-based-access-control/custom-roles')))
            }
        }
    }

    # ---- service principal / app credential hygiene ----
    foreach ($sp in $Raw.servicePrincipals) {
        $pw = ($sp.passwordCredentials | Measure-Object).Count
        $kc = ($sp.keyCredentials | Measure-Object).Count
        if (($pw + $kc) -gt 0 -and $sp.servicePrincipalType -ne 'ManagedIdentity') {
            $expired = @($sp.passwordCredentials | Where-Object { $_.endDateTime -and ([datetime]$_.endDateTime -lt (Get-Date)) })
            if ($expired.Count -gt 0) {
                $findings.Add((New-Finding -Severity 'Low' -Category 'Credential Hygiene' `
                    -Title "Service principal has expired secrets: $($sp.displayName)" `
                    -Description "App/SP '$($sp.displayName)' has $($expired.Count) expired client secret(s) still present." `
                    -Principal $sp.displayName -PrincipalType 'ServicePrincipal' -Evidence "$($expired.Count) expired secrets" `
                    -Recommendation "Remove unused credentials; prefer workload identity federation over long-lived secrets." `
                    -References @('https://learn.microsoft.com/entra/workload-id/workload-identity-federation')))
            }
        }
    }

    # ---- app registration takeover (owners can add credentials) ----
    foreach ($appId in $Raw.appOwners.Keys) {
        $sp = $Raw.servicePrincipals | Where-Object { $_.appId -eq $appId } | Select-Object -First 1
        if (-not $sp) { continue }
        foreach ($owner in $Raw.appOwners[$appId]) {
            Add-Node -Id $owner.id -Label ($owner.displayName ?? $owner.userPrincipalName) -Type 'User' -Data @{ upn = $owner.userPrincipalName }
            # Owner can add secret -> authenticate as the SP -> control everything the SP can
            Add-Edge -Source $owner.id -Target $sp.id -Type 'CanControl' -Label 'app owner (add credential)'
        }
    }

    # ---- derive: control over a scope implies control over principals scoped under it ----
    # (Owner/UAA on a subscription can grant itself access to managed identities etc.)
    # Handled structurally by CanEscalate edges feeding the attack-path BFS below.

    # ---- SP right-sizing (granted vs used) ----
    $spRightSizing = Invoke-SPRightSizing -Raw $Raw
    foreach ($r in $spRightSizing) {
        if ($r.verdict -eq 'Justified') { continue }
        $sev = switch ($r.verdict) {
            'ReviewGraph'    { 'High' }
            'Dormant'        { 'Medium' }
            'ReadOnly'       { 'High' }
            'ScopeReduction' { 'Medium' }
            'UnusedRoles'    { 'Medium' }
            default          { 'Low' }
        }
        $desc = switch ($r.verdict) {
            'Dormant'        { "Service principal '$($r.displayName)' holds Azure RBAC but performed no control-plane operations in the usage window — likely over-provisioned or abandoned." }
            'ReadOnly'       { "Service principal '$($r.displayName)' only performed read operations yet holds write-capable roles. Downgrade to Reader." }
            'UnusedRoles'    { "Service principal '$($r.displayName)' has role assignments that were never exercised in the usage window." }
            'ScopeReduction' { "Service principal '$($r.displayName)' is granted at a broad scope but only acts within specific resource group(s)." }
            'ReviewGraph'    { "Service principal '$($r.displayName)' holds high-risk Microsoft Graph application permissions that bypass Azure RBAC." }
            default          { "Service principal '$($r.displayName)' is write-capable at broad scope; usage analysis recommended." }
        }
        $findings.Add((New-Finding -Severity $sev -Category 'SP Right-Sizing' `
            -Title "Over-permissioned SP ($($r.verdict)): $($r.displayName)" `
            -Description $desc -Principal $r.displayName -PrincipalType $r.type `
            -Evidence (($r.recommendations) -join ' ') `
            -Recommendation (($r.remediation | Select-Object -First 3) -join '  |  ') `
            -References @('https://learn.microsoft.com/entra/id-governance/entitlement-management-access-package-create',
                          'https://learn.microsoft.com/azure/role-based-access-control/best-practices')))
    }

    # ---- attack path discovery (BFS from each identity to any tier-0 node) ----
    $attackPaths = Find-AttackPath -Nodes $nodes -Edges $edges

    # ---- additional finding: long attack paths ----
    foreach ($p in $attackPaths) {
        if ($p.length -ge 2) {
            $findings.Add((New-Finding -Severity $p.severity -Category 'Attack Path' `
                -Title "Attack path to Tier-0: $($p.title)" `
                -Description "A multi-step control path reaches a tier-0 asset: $($p.steps -join '  ->  ')" `
                -Principal $p.start -PrincipalType 'Identity' -Evidence ($p.steps -join ' -> ') `
                -Recommendation "Break the chain: remove the weakest control edge (group membership, app ownership, or broad role) along this path." `
                -References @('https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model')))
        }
    }

    # ---- stats ----
    $sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $findingsSorted = $findings | Sort-Object @{ Expression = { $sevOrder[$_.severity] } }, category
    $stats = [ordered]@{
        subscriptions     = ($Raw.subscriptions | Measure-Object).Count
        users             = ($Raw.users | Measure-Object).Count
        groups            = ($Raw.groups | Measure-Object).Count
        servicePrincipals = (@($Raw.servicePrincipals | Where-Object { $_.servicePrincipalType -ne 'ManagedIdentity' }) | Measure-Object).Count
        managedIdentities = ($Raw.managedIdentities | Measure-Object).Count
        roleAssignments   = ($Raw.roleAssignments | Measure-Object).Count
        resources         = ($Raw.resources | Measure-Object).Count
        findings          = $findings.Count
        critical          = (@($findings | Where-Object severity -eq 'Critical') | Measure-Object).Count
        high              = (@($findings | Where-Object severity -eq 'High') | Measure-Object).Count
        medium            = (@($findings | Where-Object severity -eq 'Medium') | Measure-Object).Count
        low               = (@($findings | Where-Object severity -eq 'Low') | Measure-Object).Count
        attackPaths       = ($attackPaths | Measure-Object).Count
        tier0Nodes        = (@($nodes.Values | Where-Object tier0) | Measure-Object).Count
        overPrivilegedSPs = (@($spRightSizing | Where-Object { $_.verdict -ne 'Justified' }) | Measure-Object).Count
    }

    # Risk score (0-100): weighted finding severities, capped.
    $risk = [math]::Min(100, ($stats.critical * 20) + ($stats.high * 8) + ($stats.medium * 3) + ($stats.low * 1))

    $bundle = [ordered]@{
        meta = [ordered]@{
            tool          = 'AzIAM Assessor'
            version       = $script:ToolVersion
            generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
            tenantId      = $Raw.account.tenantId
            account       = $Raw.account.user.name
            riskScore     = $risk
            subscriptions = @($Raw.subscriptions | ForEach-Object { @{ id = $_.id; name = $_.name } })
        }
        stats       = $stats
        findings    = @($findingsSorted)
        identities  = @($nodes.Values | Where-Object { $_.type -in @('User','Group','ServicePrincipal','ManagedIdentity') })
        roleAssignments = @($Raw.roleAssignments | ForEach-Object {
            @{ principalName = $_.principalName; principalType = $_.principalType; principalId = $_.principalId
               role = $_.roleDefinitionName; scope = $_.scope; subscription = $_._subscriptionId }
        })
        resources   = @($Raw.resources | ForEach-Object {
            @{ name = $_.name; type = $_.type; resourceGroup = $_.resourceGroup; location = $_.location; subscription = $_._subscriptionId }
        })
        directoryRoles = @($Raw.directoryRoles | ForEach-Object {
            @{ roleName = $_.roleName; memberCount = (@($_.members)|Measure-Object).Count
               members = @($_.members | ForEach-Object { $_.displayName ?? $_.userPrincipalName }) }
        })
        graph       = @{ nodes = @($nodes.Values); edges = @($edges) }
        attackPaths = @($attackPaths)
        spRightSizing = @($spRightSizing)
    }

    Write-Step "Analysis complete: $($findings.Count) findings, $($attackPaths.Count) attack paths, risk score $risk/100" 'OK'
    return $bundle
}

function Find-AttackPath {
    <# BFS over control edges (MemberOf, CanControl, CanEscalate, HasRole->tier0 scope) to tier-0 nodes. #>
    param([hashtable]$Nodes, [System.Collections.Generic.List[object]]$Edges)

    # adjacency: source -> list of (target, label)
    $adj = @{}
    $controlTypes = @('MemberOf', 'CanControl', 'CanEscalate', 'HasDirectoryRole', 'HasRole')
    foreach ($e in $Edges) {
        if ($e.type -in $controlTypes) {
            if (-not $adj.ContainsKey($e.source)) { $adj[$e.source] = @() }
            $adj[$e.source] += ,@($e.target, $e.label, $e.type)
        }
    }

    $tier0 = @($Nodes.Values | Where-Object tier0 | Select-Object -ExpandProperty id)
    $tier0Set = @{}; foreach ($t in $tier0) { $tier0Set[$t] = $true }
    $paths = [System.Collections.Generic.List[object]]::new()

    # Only start BFS from leaf identities (User/SP/Group), avoid starting at tier-0 itself.
    $starts = @($Nodes.Values | Where-Object { $_.type -in @('User','Group','ServicePrincipal','ManagedIdentity') -and -not $_.tier0 })

    foreach ($start in $starts) {
        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue(@{ node = $start.id; path = @($start.label); edges = @(); depth = 0 })
        $visited = @{ "$($start.id)" = $true }
        $found = $false
        while ($queue.Count -gt 0 -and -not $found) {
            $cur = $queue.Dequeue()
            if ($cur.depth -gt 6) { continue }
            foreach ($nbr in $adj[$cur.node]) {
                $tid = $nbr[0]; $label = $nbr[1]
                if ($visited.ContainsKey($tid)) { continue }
                $visited[$tid] = $true
                $tlabel = if ($Nodes.ContainsKey($tid)) { $Nodes[$tid].label } else { $tid }
                $newEdges = $cur.edges + ,@{ to = $tlabel; via = $label }
                $newPath = $cur.path + "[$label] $tlabel"
                if ($tier0Set.ContainsKey($tid)) {
                    $sev = if ($cur.depth -eq 0) { 'High' } else { 'Critical' }
                    $paths.Add([pscustomobject]@{
                        id = [guid]::NewGuid().ToString('N').Substring(0,8)
                        title = "$($start.label) -> $tlabel"
                        start = $start.label
                        target = $tlabel
                        severity = $sev
                        length = $cur.depth + 1
                        steps = $newPath
                        edges = $newEdges
                    })
                    $found = $true
                    break
                }
                $queue.Enqueue(@{ node = $tid; path = $newPath; edges = $newEdges; depth = $cur.depth + 1 })
            }
        }
    }
    # Return the most severe / longest first, cap to keep reports readable
    return @($paths | Sort-Object -Property @{Expression='length';Descending=$true} | Select-Object -First 100)
}

# ----------------------------------------------------------------------------
# Service Principal right-sizing  (config = granted, logs = used)
# ----------------------------------------------------------------------------

# Microsoft Graph application permissions considered high-risk (tenant takeover / broad data)
$script:HighRiskGraphPerms = @(
    'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
    'Directory.ReadWrite.All', 'Group.ReadWrite.All', 'GroupMember.ReadWrite.All', 'User.ReadWrite.All',
    'PrivilegedAccess.ReadWrite.AzureAD', 'Policy.ReadWrite.ConditionalAccess', 'Mail.ReadWrite',
    'Mail.Send', 'Files.ReadWrite.All', 'Sites.ReadWrite.All', 'Directory.AccessAsUser.All'
)

function Test-ActionMatch {
    <# Does granted RBAC action pattern (may contain *) cover a concrete used action? #>
    param([string]$Pattern, [string]$Action)
    if (-not $Pattern -or -not $Action) { return $false }
    if ($Pattern -eq '*') { return $true }
    $rx = '^' + [regex]::Escape($Pattern).Replace('\*', '.*') + '$'
    return [regex]::IsMatch($Action, $rx, 'IgnoreCase')
}

function Invoke-SPRightSizing {
    <#
      .SYNOPSIS  Per-SP granted-vs-used analysis with concrete remediation.
      .OUTPUTS   Array of right-sizing records for the dashboard 'SP Right-Sizing' tab.
    #>
    param([Parameter(Mandatory)][hashtable]$Raw)

    $roleDefByName = @{}
    foreach ($rd in $Raw.roleDefinitions) { if ($rd.roleName) { $roleDefByName[$rd.roleName] = $rd } }
    $days = if ($Raw.usageDays) { $Raw.usageDays } else { 90 }

    $records = [System.Collections.Generic.List[object]]::new()
    $allSps = @($Raw.servicePrincipals)

    foreach ($sp in $allSps) {
        $rbac = @($Raw.roleAssignments | Where-Object { $_.principalId -eq $sp.id })
        $graphGrants = @()
        if ($Raw.spAppRoles.ContainsKey($sp.id)) {
            foreach ($g in $Raw.spAppRoles[$sp.id]) {
                $val = $null
                if ($Raw.graphAppRoleMap.ContainsKey($g.resourceId)) { $val = $Raw.graphAppRoleMap[$g.resourceId][$g.appRoleId] }
                $graphGrants += [pscustomobject]@{
                    permission = ($val ?? $g.appRoleId); api = $g.resourceName
                    highRisk = ($script:HighRiskGraphPerms -contains $val)
                }
            }
        }
        # Skip SPs with neither RBAC nor Graph grants (nothing to right-size)
        if ($rbac.Count -eq 0 -and $graphGrants.Count -eq 0) { continue }

        # --- granted (config) ---
        $grantedRoles = foreach ($ra in $rbac) {
            $rd = $roleDefByName[$ra.roleDefinitionName]
            $actions = @(); if ($rd) { foreach ($p in $rd.permissions) { $actions += $p.actions } }
            [pscustomobject]@{
                role = $ra.roleDefinitionName; scope = $ra.scope
                scopeLevel = (Get-ScopeLevel $ra.scope); actions = $actions
                writeCapable = [bool]@($actions | Where-Object { $_ -eq '*' -or $_ -match '/(write|delete|action)$' -or $_ -match '\*$' }).Count
                exercised = $false
            }
        }

        # --- used (logs) ---
        $usage = @()
        if ($Raw.spActivity.ContainsKey($sp.id)) { $usage = $Raw.spActivity[$sp.id] }
        $usedOps = @($usage | ForEach-Object { $_.op } | Where-Object { $_ } | Select-Object -Unique)
        $scopesUsed = @($usage | ForEach-Object { $_.scopes } | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique)
        $lastActivity = @($usage | ForEach-Object { $_.lastUsed } | Sort-Object -Descending | Select-Object -First 1)
        $readOnlyUse = ($usedOps.Count -gt 0) -and -not @($usedOps | Where-Object { $_ -match '/(write|delete|action)$' }).Count
        $totalOps = @($usage | Measure-Object -Property count -Sum).Sum

        # mark which granted roles were actually exercised
        foreach ($gr in $grantedRoles) {
            foreach ($op in $usedOps) {
                if (@($gr.actions | Where-Object { Test-ActionMatch $_ $op }).Count) { $gr.exercised = $true; break }
            }
        }
        $unusedRoles = @($grantedRoles | Where-Object { -not $_.exercised })
        $broadGranted = [bool]@($grantedRoles | Where-Object { $_.scopeLevel -in @('Subscription','ManagementGroup','Root') -and $_.writeCapable }).Count

        # --- verdict + recommendations + remediation ---
        $recs = [System.Collections.Generic.List[string]]::new()
        $remed = [System.Collections.Generic.List[string]]::new()
        $verdict = 'Justified'; $op = 100

        $hasUsage = $Raw.usageAnalyzed
        if ($hasUsage -and $usedOps.Count -eq 0 -and $rbac.Count -gt 0) {
            $verdict = 'Dormant'; $op = 95
            $recs.Add("No control-plane activity in the last $days days. Candidate to remove RBAC or disable the SP after confirming it is not seasonal/batch.")
            foreach ($ra in $rbac) { $remed.Add("az role assignment delete --assignee $($sp.appId) --role `"$($ra.roleDefinitionName)`" --scope `"$($ra.scope)`"") }
        }
        elseif ($hasUsage -and $readOnlyUse -and $broadGranted) {
            $verdict = 'ReadOnly'; $op = 85
            $recs.Add("Only READ operations observed in $days days, but write-capable roles are granted. Downgrade to Reader.")
            foreach ($ra in ($rbac | Where-Object { $_.roleDefinitionName -ne 'Reader' })) {
                $remed.Add("az role assignment create --assignee $($sp.appId) --role `"Reader`" --scope `"$($ra.scope)`"")
                $remed.Add("az role assignment delete --assignee $($sp.appId) --role `"$($ra.roleDefinitionName)`" --scope `"$($ra.scope)`"")
            }
        }
        elseif ($hasUsage -and $unusedRoles.Count -gt 0 -and $unusedRoles.Count -lt $grantedRoles.Count) {
            $verdict = 'UnusedRoles'; $op = 70
            $recs.Add("$($unusedRoles.Count) of $($grantedRoles.Count) role assignment(s) were never exercised in $days days. Remove the unused ones.")
            foreach ($ra in $unusedRoles) { $remed.Add("az role assignment delete --assignee $($sp.appId) --role `"$($ra.role)`" --scope `"$($ra.scope)`"") }
        }
        elseif ($hasUsage -and $scopesUsed.Count -gt 0 -and $broadGranted) {
            # activity confined to specific RGs but granted at subscription/MG
            $subScoped = @($grantedRoles | Where-Object { $_.scopeLevel -in @('Subscription','ManagementGroup','Root') })
            if ($subScoped.Count) {
                $verdict = 'ScopeReduction'; $op = 75
                $recs.Add("Activity is confined to $($scopesUsed.Count) resource group(s) but the role is granted subscription-wide. Re-scope to just: $($scopesUsed -join ', ').")
                foreach ($ra in $subScoped) {
                    foreach ($rg in $scopesUsed) { $remed.Add("az role assignment create --assignee $($sp.appId) --role `"$($ra.role)`" --scope `"$rg`"") }
                    $remed.Add("az role assignment delete --assignee $($sp.appId) --role `"$($ra.role)`" --scope `"$($ra.scope)`"")
                }
            }
        }
        elseif (-not $hasUsage -and $broadGranted) {
            $verdict = 'ReviewNoLogs'; $op = 60
            $recs.Add("Write-capable role at broad scope. Re-run with -AnalyzeUsage to confirm whether these permissions are actually used.")
        }

        # Graph application-permission review (independent of RBAC usage)
        $highRiskGraph = @($graphGrants | Where-Object highRisk)
        if ($highRiskGraph.Count) {
            if ($op -lt 80) { $op = 80 }
            if ($verdict -eq 'Justified') { $verdict = 'ReviewGraph' }
            $recs.Add("Holds high-risk Graph application permission(s): $(( $highRiskGraph.permission ) -join ', '). These bypass RBAC entirely — remove any not required.")
            foreach ($hr in $highRiskGraph) {
                $remed.Add("# Review/remove Graph app permission '$($hr.permission)' in Entra > App registrations > $($sp.displayName) > API permissions")
            }
        }

        $records.Add([pscustomobject]@{
            id            = $sp.id
            appId         = $sp.appId
            displayName   = $sp.displayName
            type          = if ($sp.servicePrincipalType -eq 'ManagedIdentity') { 'ManagedIdentity' } else { 'ServicePrincipal' }
            enabled       = $sp.accountEnabled
            verdict       = $verdict
            overprivilege = $op
            grantedRoles  = @($grantedRoles | ForEach-Object { @{ role = $_.role; scope = $_.scope; scopeLevel = $_.scopeLevel; exercised = $_.exercised; writeCapable = $_.writeCapable } })
            graphPermissions = @($graphGrants | ForEach-Object { @{ permission = $_.permission; api = $_.api; highRisk = $_.highRisk } })
            usage         = @{ analyzed = $Raw.usageAnalyzed; windowDays = $days; totalOperations = ([int]$totalOps)
                               distinctOps = $usedOps.Count; readOnly = $readOnlyUse; lastActivity = $lastActivity
                               scopesUsed = @($scopesUsed); operations = @($usage | Sort-Object -Property count -Descending | Select-Object -First 25) }
            recommendations = @($recs)
            remediation   = @($remed)
        })
    }

    return @($records | Sort-Object -Property overprivilege -Descending)
}

Export-ModuleMember -Function Invoke-AzCollection, Invoke-AzAnalysis, Invoke-SPRightSizing, Test-AzLogin, Write-Step
