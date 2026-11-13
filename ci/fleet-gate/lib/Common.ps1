# fleet-gate common helpers. Windows PowerShell 5.1 compatible (also runs on pwsh 7).
# ASCII only: 5.1 reads BOM-less scripts as ANSI.

$script:FgFixturePath = '(?i)(?:^|/)(?:tests?|__tests__|specs?|fixtures?|__fixtures__|testdata|test-data|mocks?|__mocks__)(?:/|$)|[._-](?:test|spec)\.[a-z0-9]+$'
$script:FgFake = '(?i)example|dummy|fake|sample|placeholder|changeme|redacted|invalid|xxxx|lorem'
$script:FgEmptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
$script:FgRank = @{ 'PASS' = 0; 'IGNORED' = 0; 'WARN' = 1; 'FAIL' = 2 }

function New-FgFinding {
  param([string]$Check, [string]$Kind, [string]$Severity, [string]$Path, [int]$Line = 0, [string]$Match = '', [string]$Note = '')
  [pscustomobject]@{ Check = $Check; Kind = $Kind; Severity = $Severity; Path = $Path; Line = $Line; Match = $Match; Note = $Note }
}

function Test-FgFixturePath { param([string]$Path) return ($Path -match $script:FgFixturePath) }
function Test-FgFake { param([string]$Text) return ($Text -match $script:FgFake) }

function Get-FgWorstSeverity {
  param([object[]]$Findings)
  $worst = 'PASS'
  foreach ($f in @($Findings)) {
    if ($null -eq $f) { continue }
    if ($script:FgRank[$f.Severity] -gt $script:FgRank[$worst]) { $worst = $f.Severity }
  }
  return $worst
}

function Read-FgTsv {
  # Reads a tab-separated data file, skipping blank lines and # comments.
  param([string]$Path, [int]$MinFields = 2)
  $rows = New-Object System.Collections.Generic.List[object]
  foreach ($l in [System.IO.File]::ReadAllLines($Path)) {
    if ($l -match '^\s*(#|$)') { continue }
    $parts = $l -split "`t"
    if ($parts.Count -lt $MinFields) { continue }
    $rows.Add($parts)
  }
  return $rows
}

function Read-FgAllowlist {
  # Merges one or more allowlist files (<kind>:<regex>). Missing files are skipped.
  param([string[]]$Paths)
  $a = @{ path = @(); match = @(); line = @(); rule = @(); fingerprint = @(); retired = @(); errors = @() }
  foreach ($p in @($Paths)) {
    if ([string]::IsNullOrEmpty($p) -or -not (Test-Path -LiteralPath $p)) { continue }
    foreach ($l in [System.IO.File]::ReadAllLines($p)) {
      if ($l -match '^\s*(#|$)') { continue }
      if ($l -notmatch '^\s*([a-z]+)\s*:\s?(.*)$') { continue }
      $k = $Matches[1]; $v = $Matches[2]
      # strip a trailing "   # comment" (two or more spaces then #)
      $v = $v -replace '\s{2,}#.*$', ''
      if (-not $a.ContainsKey($k) -or $k -eq 'errors') { $a.errors += "unknown kind '$k'"; continue }
      try { $null = [regex]::new($v); $a[$k] += $v } catch { $a.errors += "bad regex '$v'" }
    }
  }
  return $a
}

function Test-FgAnyMatch {
  param([string]$Text, [string[]]$Patterns)
  foreach ($re in @($Patterns)) { if ($re -and $Text -match $re) { return $true } }
  return $false
}

function Read-FgPublicHosts {
  # Loads data/public-hosts.json (and an optional repo .fleet-gate/public-hosts.json). PS 5.1 safe.
  param([string[]]$Paths)
  $r = @{ hosts = @(); secret = @() }
  foreach ($p in @($Paths)) {
    if ([string]::IsNullOrEmpty($p) -or -not (Test-Path -LiteralPath $p)) { continue }
    try { $j = [System.IO.File]::ReadAllText($p) | ConvertFrom-Json } catch { continue }
    foreach ($h in @($j.hosts)) { if ($h.host) { $r.hosts += ([string]$h.host).ToLowerInvariant().TrimStart('.') } }
    foreach ($q in @($j.secretQueryParams)) { if ($q) { $r.secret += ([string]$q).ToLowerInvariant() } }
  }
  return $r
}

function Test-FgPublicUrlMatch {
  # Returns 'IGNORED' (doc link), 'WARN' (code) or $null (no allowance) for a host match on a line.
  # Allowed only when the host sits inside an https:// URL with no userinfo, the host is on the
  # public list (exact or subdomain), and no query parameter looks like a secret.
  param([string]$Path, [string]$Match, [string]$LineText, $Public)
  if (-not $Public -or @($Public.hosts).Count -eq 0 -or -not $LineText) { return $null }
  $h = $Match.ToLowerInvariant()
  $ok = $false
  foreach ($e in @($Public.hosts)) { if ($h -eq $e -or $h.EndsWith('.' + $e)) { $ok = $true; break } }
  if (-not $ok) { return $null }
  $found = $false
  foreach ($u in [regex]::Matches($LineText, '(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"''`)\]]+')) {
    $url = $u.Value
    if ($url -notmatch '(?i)^([a-z][a-z0-9+.-]*)://([^/?#]*)') { continue }
    $scheme = $Matches[1].ToLowerInvariant(); $auth = $Matches[2].ToLowerInvariant()
    $hostPart = ($auth -split ':')[0]
    if ($auth.Contains('@')) { if ($auth -match [regex]::Escape($h)) { return $null } else { continue } }
    if ($hostPart -ne $h) { continue }
    if ($scheme -ne 'https') { return $null }
    $qi = $url.IndexOf('?')
    if ($qi -ge 0) {
      foreach ($kv in ($url.Substring($qi + 1) -split '[&#]')) {
        $k = (($kv -split '=')[0]).ToLowerInvariant()
        if ($Public.secret -contains $k) { return $null }
      }
    }
    $found = $true
  }
  if (-not $found) { return $null }
  $p = $Path.Replace('\', '/')
  if ($p -match '(?i)\.(md|markdown|txt|rst|adoc)$' -or $p -match '(?i)(^|/)(docs?|LICENSE|NOTICE)(/|$)') { return 'IGNORED' }
  return 'WARN'
}

function Resolve-FgContentSeverity {
  # Applies the allowlist and built-in ignores to one content finding.
  # Returns @(severity, note).
  param([string]$Severity, [string]$Path, [string]$Match, [string]$LineText, $Allow, [string]$Note = '')
  if ($Allow) {
    if (Test-FgAnyMatch $Path $Allow.path) { return @('IGNORED', 'allowlist path') }
    if (Test-FgAnyMatch $Match $Allow.match) { return @('IGNORED', 'allowlist match') }
    if ($LineText -and (Test-FgAnyMatch $LineText $Allow.line)) { return @('IGNORED', 'allowlist line') }
  }
  if (Test-FgFake $Match) { return @('IGNORED', 'obvious fake value') }
  if (Test-FgFixturePath $Path) {
    if ($LineText -and (Test-FgFake $LineText)) { return @('IGNORED', 'fake test fixture') }
    $n = @($Note, 'test/fixture path') | Where-Object { $_ }
    return @('WARN', ($n -join '; '))
  }
  return @($Severity, $Note)
}

function ConvertFrom-FgDiff {
  # Parses `git diff -U0` text into added lines: Path, Line, Text.
  param([string[]]$DiffLines)
  $out = New-Object System.Collections.Generic.List[object]
  $path = ''; $ln = 0
  foreach ($l in @($DiffLines)) {
    if ($null -eq $l) { continue }
    $l = $l.TrimEnd("`r")
    if ($l.StartsWith('+++ ')) {
      $p = $l.Substring(4)
      if ($p.StartsWith('"') -and $p.EndsWith('"')) { $p = $p.Substring(1, $p.Length - 2) }
      if ($p.StartsWith('b/')) { $p = $p.Substring(2) }
      if ($p -eq '/dev/null') { $p = '' }
      $path = $p; continue
    }
    if ($l -match '^@@ -\S+ \+(\d+)') { $ln = [int]$Matches[1]; continue }
    if ($l -match '^(?:diff --git|index |--- |new file|deleted file|similarity|rename |old mode|new mode|Binary files)') { continue }
    if ($l.StartsWith('+') -and $path -ne '') {
      $out.Add([pscustomobject]@{ Path = $path; Line = $ln; Text = $l.Substring(1) })
      $ln++
    }
  }
  return $out
}

function Invoke-FgGit {
  # Runs git in the repo and returns stdout lines. Stderr is dropped (5.1 turns native
  # stderr into errors under -ErrorAction Stop). Throws on a non-zero exit unless -AllowFail.
  param([string]$RepoPath, [string[]]$GitArgs, [switch]$AllowFail)
  $old = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out = & git -C $RepoPath -c core.quotepath=false @GitArgs 2>$null
    $code = $LASTEXITCODE
  } finally { $ErrorActionPreference = $old }
  if ($code -ne 0 -and -not $AllowFail) { throw "git $($GitArgs -join ' ') failed with exit code $code" }
  return @($out)
}

function Get-FgTrackedFiles {
  param([string]$RepoPath)
  $files = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('ls-files'))
  return @($files | Where-Object { $_ })
}

function Test-FgTextFile {
  # True when the file exists, is at most MaxBytes, and has no NUL byte in its first 8 KB.
  param([string]$FullPath, [long]$MaxBytes = 2097152)
  if (-not (Test-Path -LiteralPath $FullPath -PathType Leaf)) { return $false }
  $fi = New-Object System.IO.FileInfo($FullPath)
  if ($fi.Length -gt $MaxBytes) { return $false }
  $fs = [System.IO.File]::OpenRead($FullPath)
  try {
    $buf = New-Object byte[] 8192
    $n = $fs.Read($buf, 0, $buf.Length)
    for ($i = 0; $i -lt $n; $i++) { if ($buf[$i] -eq 0) { return $false } }
  } finally { $fs.Dispose() }
  return $true
}

function Format-FgAnnotation {
  # Escapes a GitHub workflow command value.
  param([string]$Text)
  if ($null -eq $Text) { return '' }
  return ($Text -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A')
}

function Add-FgGithubFile {
  # Appends UTF-8 (no BOM) text to a GitHub file command target (GITHUB_OUTPUT, GITHUB_STEP_SUMMARY).
  param([string]$Path, [string]$Text)
  if ([string]::IsNullOrEmpty($Path)) { return }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::AppendAllText($Path, $Text, $enc)
}
