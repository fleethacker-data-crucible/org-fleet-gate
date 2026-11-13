<#
.SYNOPSIS
  fleet-gate: the org-wide PR check for fleethacker-data-crucible (Windows PowerShell 5.1).
.DESCRIPTION
  Runs on a checked-out PR merge ref and compares it with the PR base. Prints a
  PASS/WARN/FAIL table and path:line findings, and exits 1 on any FAIL.
  Read-only: it never writes to GitHub. With -BaseSha empty it runs a full scan
  (every tracked file counts as added).
.EXAMPLE
  powershell -NoProfile -File Invoke-FleetGate.ps1 -RepoPath . -BaseSha $env:BASE_SHA
#>
[CmdletBinding()]
param(
  [string]$RepoPath = '.',
  [string]$BaseSha = '',
  [string]$AllowlistPath = '',
  [string]$PolicyPath = '',
  [string]$GitleaksPath = '',
  [switch]$SkipGitleaks,
  [string]$TempDir = '',
  [double]$MaxSizeMB = 5,
  [string]$JsonPath = ''
)
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'FleetGate.psm1')) -Force

$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path
if (-not $TempDir) { $TempDir = $env:RUNNER_TEMP }
if (-not $TempDir) { $TempDir = [System.IO.Path]::GetTempPath() }
$TempDir = [System.IO.Path]::Combine($TempDir, 'fleet-gate')
$null = New-Item -ItemType Directory -Path $TempDir -Force

$full = [string]::IsNullOrEmpty($BaseSha)
$mergeBase = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'  # git empty tree
if (-not $full) {
  $mb = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('merge-base', $BaseSha, 'HEAD') -AllowFail)
  if ($mb -and $mb[0]) { $mergeBase = $mb[0].Trim() } else { $mergeBase = $BaseSha }
}
$head = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('rev-parse', 'HEAD'))[0].Trim()
Write-Host "fleet-gate: repo $RepoPath, head $head, base $(if ($full) { '(full scan)' } else { $mergeBase })"

$allowFiles = @((Get-FgDataPath 'allowlist.default.txt'))
if (-not $AllowlistPath) { $AllowlistPath = [System.IO.Path]::Combine($RepoPath, '.fleet-gate', 'allowlist.txt') }
$allowFiles += $AllowlistPath
$allow = Read-FgAllowlist -Paths $allowFiles
# Org-wide public hosts only (a PR can't widen it from the checked repo).
$public = Read-FgPublicHosts -Paths @((Get-FgDataPath 'public-hosts.json'))
foreach ($e in $allow.errors) { Write-Host "::warning::fleet-gate allowlist: $(Format-FgAnnotation $e)" }
# Repo policy from the PR base commit (never the head); a full scan reads the working tree.
$policyBase = $BaseSha; if ($full) { $policyBase = '' }
$policy = Get-FgPolicy -RepoPath $RepoPath -BaseRef $policyBase -PolicyPath $PolicyPath
foreach ($e in $policy.errors) { Write-Host "::warning::fleet-gate policy: $(Format-FgAnnotation $e)" }
if ($policy.visibility -eq 'private-permanent') { Write-Host 'fleet-gate: policy visibility private-permanent; publication-only rules (private IPs, hosts, paths, emails) report WARN' }

$diff = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('diff', '--no-color', '--no-ext-diff', '--no-renames', '-U0', $mergeBase, 'HEAD'))
$added = @(ConvertFrom-FgDiff -DiffLines $diff)
$changed = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('diff', '--no-renames', '--name-only', $mergeBase, 'HEAD') | Where-Object { $_ })
Write-Host "fleet-gate: $($changed.Count) changed files, $($added.Count) added lines"

$findings = New-Object System.Collections.Generic.List[object]
$errors = @{}
function Add-Results { param([string]$Check, [scriptblock]$Block)
  try { foreach ($x in @(& $Block)) { if ($x) { $findings.Add($x) } } }
  catch { $errors[$Check] = $_.Exception.Message; Write-Host "::error::fleet-gate $Check failed: $(Format-FgAnnotation $_.Exception.Message)" }
}

Add-Results 'sensitive' { Find-FgSensitiveAdded -AddedLines $added -Patterns (Read-FgTsv (Get-FgDataPath 'sensitive-patterns.tsv') 3) -Allow $allow -Public $public }
if (-not $SkipGitleaks) {
  Add-Results 'sensitive' {
    $gl = $GitleaksPath
    if (-not $gl) { $gl = Install-FgGitleaks -Dest $TempDir }
    $range = ''; if (-not $full) { $range = "$mergeBase..HEAD" }
    Invoke-FgGitleaks -GitleaksPath $gl -RepoPath $RepoPath -LogRange $range -TempDir $TempDir -Allow $allow
  }
}
Add-Results 'endpoints' { Find-FgEndpoints -RepoPath $RepoPath -Patterns (Read-FgTsv (Get-FgDataPath 'endpoint-patterns.tsv') 3) -Allow $allow -Public $public }
Add-Results 'binaries' { Find-FgBinaries -RepoPath $RepoPath -BaseSha $mergeBase -BinaryExt (Read-FgBinaryExtensions (Get-FgDataPath 'binary-extensions.txt')) -MaxSizeMB $MaxSizeMB -Allow $allow }
Add-Results 'workflows' { Find-FgWorkflows -RepoPath $RepoPath -ChangedPaths $changed }
Add-Results 'house' { Test-FgLicense -RepoPath $RepoPath }
Add-Results 'house' { Find-FgRetiredNames -AddedLines $added -Patterns (Read-FgTsv (Get-FgDataPath 'retired-names.tsv') 2) -Allow $allow }
Add-Results 'house' { Find-FgRetiredNamesRepo -RepoPath $RepoPath -Patterns (Read-FgTsv (Get-FgDataPath 'retired-names.tsv') 2) -Allow $allow -Severity (Get-FgRepoScanSeverity (Get-FgDataPath 'retired-names-repo.setting')) }
Add-Results 'house' { Find-FgListeners -RepoPath $RepoPath -Patterns (Read-FgTsv (Get-FgDataPath 'listener-patterns.tsv') 3) -Allow $allow }
Add-Results 'contrast' { Find-FgContrastInRepo -RepoPath $RepoPath -ChangedPaths $changed -FullScan:$full }
Add-Results 'security' { Find-FgSecurityChanges -ChangedPaths $changed -AddedLines $added -Patterns (Read-FgTsv (Get-FgDataPath 'security-paths.tsv') 3) }

$adjusted = @(Resolve-FgPolicySeverity -Findings $findings.ToArray() -Policy $policy -Visibility (Get-FgRepoVisibility))
$findings.Clear(); foreach ($x in $adjusted) { $findings.Add($x) }
$rows = Get-FgSummaryRows -Findings $findings -Errors $errors
Write-Host (Format-FgReport -Rows $rows -Findings $findings)
if ($env:GITHUB_ACTIONS -eq 'true') { Write-FgAnnotations -Findings $findings }

$overall = Get-FgWorstSeverity @($rows | ForEach-Object { [pscustomobject]@{ Severity = $_.Result } })
$sec = @($findings | Where-Object { $_.Check -eq 'security' })
$secCats = Get-FgSecuritySummary $sec
Add-FgGithubFile -Path $env:GITHUB_STEP_SUMMARY -Text (ConvertTo-FgMarkdown -Rows $rows -Findings $findings)
Add-FgGithubFile -Path $env:GITHUB_OUTPUT -Text ("result=$overall`nneeds_researcher=$(([bool]$sec.Count).ToString().ToLowerInvariant())`nsecurity_categories=$secCats`n")
if ($sec.Count -gt 0) { Write-Host "::warning::fleet-gate: security-relevant changes ($secCats); needs Researcher verdict" }
if ($JsonPath) {
  $doc = [pscustomobject]@{ head = $head; base = $mergeBase; result = $overall; rows = $rows; findings = $findings }
  [System.IO.File]::WriteAllText($JsonPath, ($doc | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
}
Write-Host "fleet-gate: overall $overall"
if ($overall -eq 'FAIL') { exit 1 }
exit 0
