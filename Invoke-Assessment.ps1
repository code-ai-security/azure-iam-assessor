<#
.SYNOPSIS
    AzIAM Assessor - Azure / Entra ID IAM security assessment (AzureHound-style).

.DESCRIPTION
    Enumerates identities, Azure RBAC role assignments, Entra directory roles and
    resources from the Azure tenant you are logged into, derives misconfiguration
    findings + control-graph attack paths, and renders an interactive HTML GUI
    with downloadable reports.

    DEFENSIVE USE ONLY: run against tenants you own or are authorized to assess.

.PARAMETER SubscriptionId
    One or more subscription IDs/names to scope to. Default: all accessible.

.PARAMETER OutputPath
    Folder for the generated dashboard + data. Default: .\output

.PARAMETER SkipGraph
    Skip Microsoft Graph (Entra) collection - use when you only have ARM access.

.PARAMETER NoLaunch
    Do not auto-open the dashboard in the browser when done.

.EXAMPLE
    pwsh .\Invoke-Assessment.ps1

.EXAMPLE
    pwsh .\Invoke-Assessment.ps1 -SubscriptionId "Prod" -OutputPath C:\reports\az
#>
[CmdletBinding()]
param(
    [string[]]$SubscriptionId,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'output'),
    [switch]$SkipGraph,
    [switch]$AnalyzeUsage,
    [int]$UsageDays = 90,
    [switch]$NoLaunch
)

# --- Requirements -----------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "ERROR: PowerShell 7+ is required (you are on $($PSVersionTable.PSVersion))." -ForegroundColor Red
    Write-Host "Install it:  winget install --id Microsoft.PowerShell -e   then run with 'pwsh'." -ForegroundColor Yellow
    exit 1
}
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Azure CLI ('az') not found. Install:  winget install -e --id Microsoft.AzureCLI" -ForegroundColor Red
    exit 1
}

Import-Module (Join-Path $PSScriptRoot 'src\AzIAM.psm1') -Force

$banner = @'
   _       ___  ___ _   _    _
  /_\  ___|_ _|/ _ \ | | |  /_\  ___ ___ ___ ___ ___ ___ _ __
 / _ \|_ /| |  | (_) |__   _|/ _ \(_-<(_-</ -_)(_-<(_-</ _ \ '_|
/_/ \_\/__|___| \__/|_|  |_|/_/ \_\/__//__/\___/__//__/\___/_|
       Azure / Entra ID IAM Security Assessment
'@
Write-Host $banner -ForegroundColor Magenta
Write-Host " Defensive assessment - authorized tenants only`n" -ForegroundColor DarkGray

try {
    $raw      = Invoke-AzCollection -SubscriptionId $SubscriptionId -SkipGraph:$SkipGraph -AnalyzeUsage:$AnalyzeUsage -UsageDays $UsageDays
    $bundle   = Invoke-AzAnalysis -Raw $raw
} catch {
    Write-Step "Fatal: $($_.Exception.Message)" 'ERR'
    exit 1
}

# --- Emit output ------------------------------------------------------------
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$json = $bundle | ConvertTo-Json -Depth 40 -Compress

# data.js  (loaded via <script> so the dashboard works from file:// with no server/CORS)
$dataJs = "window.ASSESSMENT_DATA = $json;"
Set-Content -Path (Join-Path $OutputPath 'data.js') -Value $dataJs -Encoding utf8

# Raw JSON snapshot for tooling / diffing
Set-Content -Path (Join-Path $OutputPath 'assessment.json') -Value ($bundle | ConvertTo-Json -Depth 40) -Encoding utf8

# Copy dashboard files next to the data
$dash = Join-Path $PSScriptRoot 'dashboard'
Copy-Item (Join-Path $dash 'index.html') $OutputPath -Force
Copy-Item (Join-Path $dash 'app.js')     $OutputPath -Force
Copy-Item (Join-Path $dash 'styles.css') $OutputPath -Force

$report = Join-Path $OutputPath 'index.html'
Write-Step "Dashboard written to: $report" 'OK'
Write-Step "Risk score: $($bundle.meta.riskScore)/100  |  $($bundle.stats.critical) critical, $($bundle.stats.high) high findings" 'OK'

if (-not $NoLaunch) {
    try {
        if ($IsWindows -or $env:OS -eq 'Windows_NT') { Start-Process $report }
        elseif ($IsMacOS) { & open $report }
        else { & xdg-open $report }
    } catch { Write-Step "Open manually: $report" 'INFO' }
}
