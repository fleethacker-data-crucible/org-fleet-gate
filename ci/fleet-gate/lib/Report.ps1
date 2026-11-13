# Result table, findings list, annotations, step summary and outputs.

$script:FgChecks = [ordered]@{
  sensitive = 'Sensitive content (added lines + gitleaks)'
  endpoints = 'No military/service-branch default endpoints (full repo)'
  binaries  = 'No large files / binaries'
  workflows = 'Workflow safety + PowerShell 5.1 shells on Windows runners'
  house     = 'House rules (MIT LICENSE, retired names, loopback listeners)'
  contrast  = 'Static color contrast (WCAG 2.x)'
  security  = 'Security-relevant changes (Researcher routing)'
}

function Get-FgSummaryRows {
  param([object[]]$Findings, [hashtable]$Errors)
  $rows = @()
  foreach ($k in $script:FgChecks.Keys) {
    $fs = @($Findings | Where-Object { $_ -and $_.Check -eq $k -and $_.Severity -ne 'IGNORED' -and $_.Severity -ne 'PASS' })
    $res = Get-FgWorstSeverity $fs
    $sum = ''
    $nf = @($fs | Where-Object { $_.Severity -eq 'FAIL' }).Count; $nw = @($fs | Where-Object { $_.Severity -eq 'WARN' }).Count
    if ($nf -or $nw) { $sum = "$nf FAIL, $nw WARN" } else { $sum = 'clean' }
    if ($k -eq 'security' -and $fs.Count -gt 0) { $sum = 'needs Researcher verdict: ' + (Get-FgSecuritySummary $fs) }
    if ($k -eq 'binaries' -and $nf -gt 0) { $sum += '; see the Large assets help below' }
    if ($Errors -and $Errors.ContainsKey($k)) { $res = 'FAIL'; $sum = "check error: $($Errors[$k])" }
    $rows += [pscustomobject]@{ Check = $k; Result = $res; Title = $script:FgChecks[$k]; Summary = $sum }
  }
  return $rows
}

function Format-FgReport {
  param([object[]]$Rows, [object[]]$Findings)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('fleet-gate results')
  $null = $sb.AppendLine(('{0,-7} {1,-10} {2}' -f 'RESULT', 'CHECK', 'SUMMARY'))
  foreach ($r in $Rows) { $null = $sb.AppendLine(('{0,-7} {1,-10} {2}: {3}' -f $r.Result, $r.Check, $r.Title, $r.Summary)) }
  $shown = @($Findings | Where-Object { $_ -and ($_.Severity -eq 'FAIL' -or $_.Severity -eq 'WARN') } | Sort-Object @{ Expression = { -$script:FgRank[$_.Severity] } }, Check, Path, Line)
  if ($shown.Count -gt 0) {
    $null = $sb.AppendLine(''); $null = $sb.AppendLine('Findings (path:line)')
    foreach ($f in $shown) {
      $loc = $f.Path; if ($f.Line -gt 0) { $loc = "$($f.Path):$($f.Line)" }
      $null = $sb.AppendLine(('{0,-4} {1,-10} {2}  [{3}] {4}  {5}' -f $f.Severity, $f.Check, $loc, $f.Kind, $f.Match, $f.Note))
    }
  }
  if (@($Findings | Where-Object { $_ -and $_.Check -eq 'binaries' -and $_.Severity -eq 'FAIL' }).Count -gt 0) {
    $null = $sb.AppendLine(''); $null = $sb.AppendLine('Large assets: ' + $script:FgLargeAssetHelp)
  }
  return $sb.ToString()
}

function Write-FgAnnotations {
  param([object[]]$Findings)
  foreach ($f in @($Findings | Where-Object { $_ -and ($_.Severity -eq 'FAIL' -or $_.Severity -eq 'WARN') })) {
    $lvl = 'warning'; if ($f.Severity -eq 'FAIL') { $lvl = 'error' }
    $msg = "fleet-gate $($f.Check)/$($f.Kind): $($f.Match) $($f.Note)"
    if ($f.Check -eq 'binaries' -and $f.Severity -eq 'FAIL') { $msg += ' -- ' + $script:FgLargeAssetHelp }
    $loc = ''
    if ($f.Path) { $loc = " file=$(Format-FgAnnotation $f.Path)"; if ($f.Line -gt 0) { $loc += ",line=$($f.Line)" } }
    Write-Host "::$lvl$loc::$(Format-FgAnnotation $msg)"
  }
}

function ConvertTo-FgMarkdown {
  param([object[]]$Rows, [object[]]$Findings)
  $sb = New-Object System.Text.StringBuilder
  $null = $sb.AppendLine('## fleet-gate'); $null = $sb.AppendLine('')
  $null = $sb.AppendLine('| Result | Check | Summary |'); $null = $sb.AppendLine('|---|---|---|')
  foreach ($r in $Rows) { $null = $sb.AppendLine("| $($r.Result) | $($r.Title) | $(($r.Summary) -replace '\|', '/') |") }
  $shown = @($Findings | Where-Object { $_ -and ($_.Severity -eq 'FAIL' -or $_.Severity -eq 'WARN') })
  if ($shown.Count -gt 0) {
    $null = $sb.AppendLine(''); $null = $sb.AppendLine('| Sev | Where | Finding |'); $null = $sb.AppendLine('|---|---|---|')
    foreach ($f in ($shown | Select-Object -First 200)) {
      $loc = $f.Path; if ($f.Line -gt 0) { $loc = "$($f.Path):$($f.Line)" }
      $null = $sb.AppendLine("| $($f.Severity) | ``$loc`` | $($f.Check)/$($f.Kind): $(($f.Match + ' ' + $f.Note) -replace '\|', '/') |")
    }
  }
  if (@($Findings | Where-Object { $_ -and $_.Check -eq 'binaries' -and $_.Severity -eq 'FAIL' }).Count -gt 0) {
    $null = $sb.AppendLine(''); $null = $sb.AppendLine('**Large assets:** ' + $script:FgLargeAssetHelp)
  }
  return $sb.ToString()
}
