# House rules: MIT LICENSE, loopback-only listeners (every code file).

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
