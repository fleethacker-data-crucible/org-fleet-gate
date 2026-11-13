<#
.SYNOPSIS
  fleet-gate browser accessibility scan (axe-core + computed contrast) for the elevated runner.
.DESCRIPTION
  Re-checks the team guard from the event payload (defense in depth: the workflow's job-level
  if: is the real gate), downloads the pinned axe-core, serves each page from a loopback-only
  listener and drives headless Edge/Chrome over the DevTools protocol. Exits 1 on any FAIL.
#>
[CmdletBinding()]
param(
  [string]$RepoPath = '.',
  [string]$TempDir = '',
  [string]$AxePath = '',
  [string]$BrowserPath = '',
  [switch]$SkipGuard
)
$ErrorActionPreference = 'Stop'
Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'BrowserA11y.psm1')) -Force
if (-not $SkipGuard) {
  $g = Test-FgBrowserScanAllowed -EventName $env:FG_EVENT_NAME -Author $env:FG_PR_AUTHOR -HeadRepo $env:FG_HEAD_REPO -BaseRepo $env:FG_BASE_REPO -HeadOwner $env:FG_HEAD_OWNER
  if (-not $g.Allowed) { Write-Host "::notice::fleet-gate browser scan did not run: $($g.Reason)"; exit 0 }
  Write-Host "fleet-gate browser scan: allowed ($($g.Reason))"
}
$RepoPath = (Resolve-Path -LiteralPath $RepoPath).Path
if (-not $TempDir) { $TempDir = $env:RUNNER_TEMP }
if (-not $TempDir) { $TempDir = [System.IO.Path]::GetTempPath() }
$TempDir = [System.IO.Path]::Combine($TempDir, 'fleet-gate-browser')
$null = New-Item -ItemType Directory -Path $TempDir -Force
if (-not $AxePath) { $AxePath = Install-FgAxe -Dest $TempDir }
if (-not $BrowserPath) { $BrowserPath = Find-FgBrowser }
$pages = @(Get-FgPageList -RepoPath $RepoPath)
if ($pages.Count -eq 0) { Write-Host 'fleet-gate browser scan: no HTML pages to scan'; exit 0 }
Write-Host "fleet-gate browser scan: $($pages.Count) page(s) with $([System.IO.Path]::GetFileName($BrowserPath))"
$findings = @(Invoke-FgBrowserScan -RepoPath $RepoPath -Pages $pages -AxePath $AxePath -BrowserPath $BrowserPath -TempDir $TempDir)
$fails = @($findings | Where-Object { $_.Severity -eq 'FAIL' })
foreach ($f in $findings) { Write-Host ('{0,-4} {1}  [{2}] {3}  {4}' -f $f.Severity, $f.Path, $f.Kind, $f.Match, $f.Note) }
if ($env:GITHUB_ACTIONS -eq 'true') {
  foreach ($f in $findings) {
    $lvl = 'warning'; if ($f.Severity -eq 'FAIL') { $lvl = 'error' }
    $m = ("fleet-gate browser/$($f.Kind): $($f.Match) $($f.Note)") -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
    Write-Host "::$lvl file=$($f.Path)::$m"
  }
}
Write-Host "fleet-gate browser scan: $($fails.Count) FAIL, $(@($findings).Count - $fails.Count) WARN"
if ($fails.Count -gt 0) { exit 1 }
exit 0
