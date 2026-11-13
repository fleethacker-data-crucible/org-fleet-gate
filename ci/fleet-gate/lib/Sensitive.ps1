# Check 6 (sensitive content in added lines), gitleaks, and the full-repo endpoint scan.

function Find-FgSensitiveAdded {
  # AddedLines: output of ConvertFrom-FgDiff. Patterns: rows from sensitive-patterns.tsv.
  param([object[]]$AddedLines, [object[]]$Patterns, $Allow, $Public)
  $out = New-Object System.Collections.Generic.List[object]
  foreach ($a in @($AddedLines)) {
    if ($null -eq $a) { continue }
    foreach ($p in @($Patterns)) {
      $kind = $p[0]; $sev = $p[1]; $re = $p[2]
      foreach ($m in [regex]::Matches($a.Text, $re)) {
        $text = $m.Value; $note = ''; $s = $sev
        if ($kind -eq 'private-ip') {
          $ip = ($text -split '/')[0]
          $bad = $false
          foreach ($o in ($ip -split '\.')) { if ([int]$o -gt 255) { $bad = $true } }
          if ($bad) { continue }
          if ($text.Contains('/')) { $s = 'WARN'; $note = 'CIDR range (often generic)' }
        }
        $r = Resolve-FgContentSeverity -Severity $s -Path $a.Path -Match $text -LineText $a.Text -Allow $Allow -Note $note
        if ($kind -eq 'mil-host' -and $r[0] -eq 'FAIL') {
          $pu = Test-FgPublicUrlMatch -Path $a.Path -Match $text -LineText $a.Text -Public $Public
          if ($pu -eq 'IGNORED') { $r = @('IGNORED', 'public https doc link (data/public-hosts.json)') }
          elseif ($pu -eq 'WARN') { $r = @('WARN', 'public https host (data/public-hosts.json); runtime use must degrade offline') }
        }
        $out.Add((New-FgFinding -Check 'sensitive' -Kind $kind -Severity $r[0] -Path $a.Path -Line $a.Line -Match ($text -replace "`t", ' ') -Note $r[1]))
      }
    }
  }
  return $out
}

function Find-FgEndpoints {
  # Full-repo scan for military / service-branch default endpoints. Files: hashtable path -> text
  # (or use -RepoPath to read every tracked text file).
  param([string]$RepoPath, [hashtable]$Files, [object[]]$Patterns, $Allow, $Public)
  $out = New-Object System.Collections.Generic.List[object]
  if (-not $Files) {
    $Files = @{}
    foreach ($f in (Get-FgTrackedFiles -RepoPath $RepoPath)) {
      $full = [System.IO.Path]::Combine($RepoPath, $f)
      if (Test-FgTextFile -FullPath $full) { $Files[$f] = [System.IO.File]::ReadAllText($full) }
    }
  }
  foreach ($path in ($Files.Keys | Sort-Object)) {
    $lines = $Files[$path] -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
      $t = $lines[$i].TrimEnd("`r")
      foreach ($p in @($Patterns)) {
        foreach ($m in [regex]::Matches($t, $p[2])) {
          $r = Resolve-FgContentSeverity -Severity $p[1] -Path $path -Match $m.Value -LineText $t -Allow $Allow
          if ($r[0] -eq 'FAIL') {
            $pu = Test-FgPublicUrlMatch -Path $path -Match $m.Value -LineText $t -Public $Public
            if ($pu -eq 'IGNORED') { $r = @('IGNORED', 'public https doc link (data/public-hosts.json)') }
            elseif ($pu -eq 'WARN') { $r = @('WARN', 'public https host (data/public-hosts.json); runtime use must degrade offline') }
          }
          $out.Add((New-FgFinding -Check 'endpoints' -Kind $p[0] -Severity $r[0] -Path $path -Line ($i + 1) -Match $m.Value -Note $r[1]))
        }
      }
    }
  }
  return $out
}

# Pinned gitleaks. Bump version + hashes together, from the release's checksums file.
$script:FgGitleaks = @{
  Version = '8.30.1'
  Windows = @{ Url = 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_windows_x64.zip'; Sha256 = 'd29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e' }
  Linux   = @{ Url = 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz'; Sha256 = '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb' }
}

function Test-FgIsWindows {
  if ($PSVersionTable.PSVersion.Major -le 5) { return $true }
  return [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)
}

function Install-FgPinnedTool {
  # Downloads Url into Dest, verifies the hard-coded SHA256, and returns the file path.
  # Nothing is installed on the host: Dest is the job's temp folder.
  param([string]$Url, [string]$Sha256, [string]$Dest)
  if (-not (Test-Path -LiteralPath $Dest)) { $null = New-Item -ItemType Directory -Path $Dest -Force }
  $file = [System.IO.Path]::Combine($Dest, [System.IO.Path]::GetFileName($Url))
  if (-not (Test-Path -LiteralPath $file)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $pp = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
    try { Invoke-WebRequest -Uri $Url -OutFile $file -UseBasicParsing } finally { $ProgressPreference = $pp }
  }
  $h = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($h -ne $Sha256.ToLowerInvariant()) {
    Remove-Item -LiteralPath $file -Force
    throw "SHA256 mismatch for $Url (got $h, expected $Sha256). Not running it."
  }
  return $file
}

function Install-FgGitleaks {
  param([string]$Dest)
  if (Test-FgIsWindows) {
    $zip = Install-FgPinnedTool -Url $script:FgGitleaks.Windows.Url -Sha256 $script:FgGitleaks.Windows.Sha256 -Dest $Dest
    $dir = [System.IO.Path]::Combine($Dest, 'gitleaks')
    Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
    return [System.IO.Path]::Combine($dir, 'gitleaks.exe')
  }
  $tgz = Install-FgPinnedTool -Url $script:FgGitleaks.Linux.Url -Sha256 $script:FgGitleaks.Linux.Sha256 -Dest $Dest
  $dir = [System.IO.Path]::Combine($Dest, 'gitleaks'); $null = New-Item -ItemType Directory -Path $dir -Force
  & tar -xzf $tgz -C $dir gitleaks
  return [System.IO.Path]::Combine($dir, 'gitleaks')
}

function ConvertFrom-FgGitleaksReport {
  # Turns a gitleaks JSON report into findings, applying the allowlist.
  param([string]$Json, $Allow)
  $out = New-Object System.Collections.Generic.List[object]
  if ([string]::IsNullOrWhiteSpace($Json)) { return $out }
  $items = ConvertFrom-Json -InputObject $Json
  foreach ($g in @($items)) {
    if ($null -eq $g) { continue }
    $path = [string]$g.File; $match = [string]$g.Match; $rule = [string]$g.RuleID; $fp = [string]$g.Fingerprint
    $sev = 'FAIL'; $note = "gitleaks $rule"
    if ($g.Commit) { $note += " in commit $(([string]$g.Commit).Substring(0, [Math]::Min(12, ([string]$g.Commit).Length)))" }
    if ($Allow -and (Test-FgAnyMatch $rule $Allow.rule)) { $sev = 'IGNORED'; $note = 'allowlist rule' }
    elseif ($Allow -and (Test-FgAnyMatch $fp $Allow.fingerprint)) { $sev = 'IGNORED'; $note = 'allowlist fingerprint' }
    else {
      # --redact puts REDACTED in Match; don't let that read as an obvious fake
      $r = Resolve-FgContentSeverity -Severity $sev -Path $path -Match ($match -replace 'REDACTED', '') -LineText '' -Allow $Allow -Note $note
      $sev = $r[0]; $note = $r[1]
    }
    $out.Add((New-FgFinding -Check 'sensitive' -Kind 'gitleaks' -Severity $sev -Path $path -Line ([int]$g.StartLine) -Match $match -Note $note))
  }
  return $out
}

function Invoke-FgGitleaks {
  # Runs gitleaks over mergebase..HEAD (or the working tree when LogRange is empty), redacted.
  param([string]$GitleaksPath, [string]$RepoPath, [string]$LogRange, [string]$TempDir, $Allow)
  $report = [System.IO.Path]::Combine($TempDir, 'gitleaks-report.json')
  if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  try {
    if ($LogRange) {
      $null = & $GitleaksPath git $RepoPath "--log-opts=$LogRange" --redact --no-banner --exit-code 0 --report-format json --report-path $report 2>&1
    } else {
      $null = & $GitleaksPath dir $RepoPath --redact --no-banner --exit-code 0 --report-format json --report-path $report 2>&1
    }
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $old }
  if ($code -ne 0 -or -not (Test-Path -LiteralPath $report)) { throw "gitleaks failed (exit $code)" }
  $found = @(ConvertFrom-FgGitleaksReport -Json ([System.IO.File]::ReadAllText($report)) -Allow $Allow)
  $root = [System.IO.Path]::GetFullPath($RepoPath).TrimEnd('\', '/')
  foreach ($f in $found) {
    $p = $f.Path -replace '\\', '/'
    $r = $root -replace '\\', '/'
    if ($p.StartsWith($r + '/', [StringComparison]::OrdinalIgnoreCase)) { $f.Path = $p.Substring($r.Length + 1) }
  }
  return $found
}
