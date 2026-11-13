# Security-relevant change detector: lists what a Researcher should look at.
# It never writes labels (the gate has read-only permissions); it WARNs and sets outputs.

$script:FgProseExt = '(?i)\.(md|txt|tsv|csv|css|html?|png|svg|jpe?g|gif|ico|webp)$'

function Find-FgSecurityChanges {
  param([string[]]$ChangedPaths, [object[]]$AddedLines, [object[]]$Patterns)
  $hits = @{}
  foreach ($p in @($Patterns)) {
    $cat = $p[0]; $scope = $p[1]; $re = $p[2]
    if ($scope -eq 'path') {
      foreach ($c in @($ChangedPaths)) {
        if (-not $c -or (Test-FgFixturePath $c) -or $c -match $script:FgProseExt) { continue }
        if ($c -match $re) { $k = "$cat|$c|0"; if (-not $hits.ContainsKey($k)) { $hits[$k] = New-FgFinding 'security' $cat 'WARN' $c 0 $Matches[0] 'path; needs Researcher verdict' } }
      }
    } else {
      foreach ($a in @($AddedLines)) {
        if ($null -eq $a) { continue }
        if (Test-FgFixturePath $a.Path) { continue }
        if ($a.Path -notmatch $script:FgCodeExt) { continue }   # docs and prose don't route
        if ($a.Text -match $re) {
          $k = "$cat|$($a.Path)|line"
          if (-not $hits.ContainsKey($k)) { $hits[$k] = New-FgFinding 'security' $cat 'WARN' $a.Path $a.Line $Matches[0].Trim() 'added code; needs Researcher verdict' }
        }
      }
    }
  }
  $list = New-Object System.Collections.Generic.List[object]
  foreach ($k in ($hits.Keys | Sort-Object)) { $list.Add($hits[$k]) }
  return $list
}

function Get-FgSecuritySummary {
  # Returns "auth,crypto" style category list from security findings.
  param([object[]]$Findings)
  $cats = @($Findings | Where-Object { $_ } | ForEach-Object { $_.Kind } | Sort-Object -Unique)
  return ($cats -join ',')
}
