# House rules: MIT LICENSE, retired names (added lines), loopback-only listeners (every code file).

function Test-FgLicense {
  param([string]$RepoPath)
  $names = 'LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE', 'COPYING'
  foreach ($n in $names) {
    $p = [System.IO.Path]::Combine($RepoPath, $n)
    if (Test-Path -LiteralPath $p -PathType Leaf) {
      $t = [System.IO.File]::ReadAllText($p)
      if ($t -match '(?i)\bMIT License\b' -or $t -match '(?i)Permission is hereby granted, free of charge') {
        return (New-FgFinding 'house' 'license' 'PASS' $n 0 'MIT' '')
      }
      return (New-FgFinding 'house' 'license' 'FAIL' $n 0 'not MIT' 'the org license is MIT; replace LICENSE with the MIT text')
    }
  }
  return (New-FgFinding 'house' 'license' 'FAIL' 'LICENSE' 0 'missing' 'add an MIT LICENSE file at the repo root')
}

function Find-FgRetiredNames {
  param([object[]]$AddedLines, [object[]]$Patterns, $Allow)
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($a in @($AddedLines)) {
    if ($null -eq $a) { continue }
    foreach ($p in @($Patterns)) {
      $m = [regex]::Match($a.Text, $p[1])
      while ($m.Success) {
        # Compatibility wire identifiers are not a product label. Examine every
        # occurrence so a real retired name later on the same line still fails.
        $before = $a.Text.Substring(0, $m.Index)
        $after = $a.Text.Substring($m.Index + $m.Length)
        $wireHeader = $m.Value -ceq ('A' + 'RC') -and $before -cmatch '(^|[^A-Za-z0-9_-])X-$' -and $after -cmatch '^-Client($|[^A-Za-z0-9_-])'
        # ECharts exports its geometric shape as a property and uses its label
        # beside Angle. Limit this exception to the vendor bundle and syntax.
        $geometry = $m.Value -ceq ('A' + 'rc') -and $a.Path -match '(?i)(^|/)echarts[-.][^/]*\.(m?js)$' -and
          ($after -match '^:\(\)=>' -or ($before.EndsWith('?'+[char]96) -and $after.StartsWith(([string][char]96)+':'+[char]96+'Angle')))
        if (-not ($wireHeader -or $geometry)) { break }
        $m = $m.NextMatch()
      }
      if ($m.Success) {
        $sev = $p[0]; $note = $p[2]
        if ($Allow -and ((Test-FgAnyMatch $a.Path $Allow.path) -or (Test-FgAnyMatch $m.Value $Allow.match) -or (Test-FgAnyMatch $a.Text $Allow.line) -or (Test-FgAnyMatch $a.Path $Allow.retired))) { $sev = 'IGNORED'; $note = 'allowlist' }
        elseif (Test-FgFixturePath $a.Path) { $sev = 'WARN'; $note = "$note; test/fixture path" }
        $out.Add((New-FgFinding 'house' 'retired-name' $sev $a.Path $a.Line $m.Value $note))
        break   # one finding per line
      }
    }
  }
  return $out
}

function Get-FgRepoScanSeverity {
  # One setting line (WARN or FAIL) in data/retired-names-repo.setting; anything else means WARN.
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return 'WARN' }
  foreach ($l in [System.IO.File]::ReadAllLines($Path)) {
    $t = $l.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    if ($t -ceq 'FAIL') { return 'FAIL' }
    return 'WARN'
  }
  return 'WARN'
}

$script:FgRepoScanSkip = '(?i)^(CHANGELOG\.md$|ci/fleet-gate/data/|docs/reports/)'

function Find-FgRetiredNamesRepo {
  # Whole-repo scan with the same patterns as the added-line check. A hit that would FAIL there
  # is reported with -Severity (default WARN) so a repo can be cleaned up before the gate blocks.
  param([string]$RepoPath, [object[]]$Patterns, $Allow, [string]$Severity = 'WARN')
  $lines = New-Object System.Collections.Generic.List[object]
  foreach ($f in (Get-FgTrackedFiles -RepoPath $RepoPath)) {
    if ($f -match $script:FgRepoScanSkip -or $f -match $script:FgSkipDirs) { continue }
    $full = [System.IO.Path]::Combine($RepoPath, $f)
    if (-not (Test-FgTextFile -FullPath $full)) { continue }
    $n = 0
    foreach ($t in [System.IO.File]::ReadAllLines($full)) {
      $n++
      $lines.Add([pscustomobject]@{ Path = $f; Line = $n; Text = $t })
    }
  }
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($r in @(Find-FgRetiredNames -AddedLines $lines -Patterns $Patterns -Allow $Allow)) {
    $sev = $r.Severity
    if ($sev -eq 'FAIL') { $sev = $Severity }
    $out.Add((New-FgFinding 'house' 'retired-name-repo' $sev $r.Path $r.Line $r.Match $r.Note))
  }
  return $out
}

$script:FgCodeExt = '(?i)\.(ps1|psm1|psd1|cs|js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|bat|cmd|vbs|json|toml|ya?ml|config|ini)$'
$script:FgSkipDirs = '(?i)(?:^|/)(?:node_modules|dist|build|out|bin|obj|target|vendor|third_party|\.git)/|\.min\.js$'

function Find-FgListeners {
  # Files: hashtable path -> text (or -RepoPath to read every tracked code file).
  param([string]$RepoPath, [hashtable]$Files, [object[]]$Patterns, $Allow)
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Files) {
    $Files = @{}
    foreach ($f in (Get-FgTrackedFiles -RepoPath $RepoPath)) {
      if ($f -notmatch $script:FgCodeExt -or $f -match $script:FgSkipDirs) { continue }
      $full = [System.IO.Path]::Combine($RepoPath, $f)
      if (Test-FgTextFile -FullPath $full) { $Files[$f] = [System.IO.File]::ReadAllText($full) }
    }
  }
  foreach ($path in ($Files.Keys | Sort-Object)) {
    $lines = $Files[$path] -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $t = $lines[$i].TrimEnd("`r")
      if ($t -match '^\s*(#|//|\*|<#|REM\b|::)') { continue }   # comment lines
      foreach ($p in @($Patterns)) {
        foreach ($m in [regex]::Matches($t, $p[2])) {
          $sev = $p[1]; $note = $p[3]
          if ($Allow -and ((Test-FgAnyMatch $path $Allow.path) -or (Test-FgAnyMatch $t $Allow.line))) { $sev = 'IGNORED'; $note = 'allowlist' }
          elseif (Test-FgFixturePath $path) { if ($sev -eq 'FAIL') { $sev = 'WARN' }; $note = "$note; test/fixture path" }
          $out.Add((New-FgFinding 'house' "listener-$($p[0])" $sev $path ($i + 1) $m.Value.Trim() $note))
        }
      }
    }
  }
  return $out
}
