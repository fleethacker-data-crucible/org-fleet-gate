# Check 8b (dangerous workflow patterns, changed workflow files) and the shell rule
# (every workflow file): run steps on Windows runners use Windows PowerShell 5.1
# (`shell: powershell`); jobs on Linux runners may use bash, sh, python or pwsh.

$script:FgUntrusted = '\$\{\{\s*(?:github\.head_ref|github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|pages\.[^}]*\.page_name|commits\.[^}]*\.(?:message|author\.(?:email|name))|head_commit\.(?:message|author\.(?:email|name))|workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:email|name)))))[^}]*\}\}'
$script:FgPrRef = '(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.event\.workflow_run\.head_(?:sha|branch)|github\.head_ref|refs/pull/)'

function Get-FgIndent { param([string]$Line) return ($Line.Length - $Line.TrimStart(' ').Length) }

function Find-FgWorkflowDanger {
  # Port of pr-gate scan-workflows.pl. Lines: the workflow file's lines.
  param([string]$Path, [string[]]$Lines)
  $out = New-Object System.Collections.Generic.List[object]
  $all = $Lines -join "`n"
  $priv = ''
  if ($all -match '\bpull_request_target\b') { $priv = 'pull_request_target' }
  elseif ($all -match '(?m)(?:^|[\s,\[])workflow_run\s*(?::|[,\]]|$)') { $priv = 'workflow_run' }
  if ($priv) { $out.Add((New-FgFinding 'workflows' 'privileged-trigger' 'WARN' $Path 0 $priv 'runs with write token/secrets on untrusted PR events')) }
  if ($all -notmatch '(?m)^permissions\s*:') { $out.Add((New-FgFinding 'workflows' 'token-permissions' 'WARN' $Path 0 'no top-level permissions:' 'set least-privilege permissions (e.g. contents: read)')) }
  $inRun = $false; $runIndent = -1
  for ($i = 0; $i -lt $Lines.Count; $i++) {
    $l = $Lines[$i].TrimEnd("`r"); $n = $i + 1
    $ind = Get-FgIndent $l
    if ($inRun -and $l -match '\S' -and $ind -le $runIndent) { $inRun = $false }
    $isRun = $l -match '^\s*(?:-\s*)?run\s*:'
    if ($isRun) {
      $null = $l -match '^(\s*(?:-\s*)?)'; $runIndent = $Matches[1].Length
      if ($l -match 'run\s*:\s*[|>][-+]?\s*$') { $inRun = $true }
    }
    if (($inRun -or $isRun) -and $l -match "($script:FgUntrusted)") {
      $out.Add((New-FgFinding 'workflows' 'script-injection' 'FAIL' $Path $n $Matches[1] 'untrusted context expanded inside run:; pass via env: instead'))
    }
    if ($l -match '^\s*(?:-\s*)?uses\s*:\s*["'']?([^\s"''#]+)') {
      $u = $Matches[1]
      if (-not $u.StartsWith('./')) {
        if ($u.StartsWith('docker://')) {
          if ($u -notmatch '@sha256:[0-9a-f]{64}$') { $out.Add((New-FgFinding 'workflows' 'unpinned-action' 'WARN' $Path $n $u 'docker image not pinned by digest')) }
        } elseif ($u -match '@([^@]+)$') {
          if ($Matches[1] -notmatch '^[0-9a-f]{40}$') { $out.Add((New-FgFinding 'workflows' 'unpinned-action' 'WARN' $Path $n $u 'pin third-party actions to a full commit SHA')) }
        } else { $out.Add((New-FgFinding 'workflows' 'unpinned-action' 'WARN' $Path $n $u 'no ref')) }
      }
    }
    if ($priv -and $l -match "^\s*(?:-\s*)?ref\s*:.*$script:FgPrRef") {
      $out.Add((New-FgFinding 'workflows' 'untrusted-checkout' 'FAIL' $Path $n $l.Trim() "checks out PR head code under $priv (pwn request)"))
    }
    if ($l -match 'permissions\s*:\s*write-all') { $out.Add((New-FgFinding 'workflows' 'token-permissions' 'WARN' $Path $n 'write-all' 'broad token permissions')) }
    if ($l -match '(?i)(?:curl|wget|iwr|Invoke-WebRequest)[^|]*\|\s*(?:ba|z)?sh\b|\|\s*iex\b') { $out.Add((New-FgFinding 'workflows' 'curl-pipe-shell' 'WARN' $Path $n $l.Trim() 'unpinned remote script piped to a shell')) }
    if ($l -match '^\s*secrets\s*:\s*inherit') { $out.Add((New-FgFinding 'workflows' 'secrets-inherit' 'WARN' $Path $n 'secrets: inherit' 'all secrets passed to a reusable workflow')) }
  }
  return $out
}

function Get-FgDefaultShell {
  # Finds `defaults: run: shell:` in the block starting at StartIndex with key indent KeyIndent.
  param([string[]]$Lines, [int]$Start, [int]$End, [int]$KeyIndent)
  for ($i = $Start; $i -lt $End; $i++) {
    $l = $Lines[$i]
    if ($l -match '^\s*defaults\s*:' -and (Get-FgIndent $l) -eq $KeyIndent) {
      for ($j = $i + 1; $j -lt $End; $j++) {
        $m = $Lines[$j]
        if ($m -notmatch '\S' -or $m -match '^\s*#') { continue }
        if ((Get-FgIndent $m) -le $KeyIndent) { break }
        if ($m -match '^\s*shell\s*:\s*(.+?)\s*(?:#.*)?$') { return $Matches[1].Trim('"', "'") }
      }
    }
  }
  return ''
}

function Get-FgUncommentedText {
  # Drops a trailing ` # comment` that is outside quotes and outside ${{ }}.
  param([string]$Text)
  $q = ''; $depth = 0
  for ($i = 0; $i -lt $Text.Length; $i++) {
    $c = $Text[$i]
    if ($q) { if ($c -eq $q) { $q = '' }; continue }
    if ($i + 2 -lt $Text.Length -and $Text.Substring($i, 3) -eq '${{') { $depth++; $i += 2; continue }
    if ($depth -gt 0 -and $i + 1 -lt $Text.Length -and $Text.Substring($i, 2) -eq '}}') { $depth--; $i++; continue }
    if ($c -eq "'" -or $c -eq '"') { $q = [string]$c; continue }
    if ($c -eq '#' -and $depth -eq 0 -and ($i -eq 0 -or [char]::IsWhiteSpace($Text[$i - 1]))) { return $Text.Substring(0, $i).TrimEnd() }
  }
  return $Text
}

function Get-FgLabelKind {
  # One runner label: 'windows', 'macos', 'linux', 'neutral' (fits any OS) or 'other'.
  param([string]$Label)
  $x = $Label.Trim().Trim('"', "'").Trim()
  if ($x -match '(?i)windows|win11|win10|headless|powershell51') { return 'windows' }
  if ($x -match '(?i)macos') { return 'macos' }
  if ($x -match '(?i)ubuntu|linux') { return 'linux' }
  if ($x -match '(?i)^(?:self-hosted|x64|x86|arm|arm64|docker)$') { return 'neutral' }
  return 'other'
}

function Get-FgLiteralLabel {
  # Splits one string literal from a runs-on expression into labels. A JSON array or
  # object literal (as in fromJSON('["self-hosted","linux"]')) gives its string values.
  param([string]$Literal)
  $t = $Literal.Trim()
  if ($t.StartsWith('[') -or $t.StartsWith('{')) {
    $vals = @()
    foreach ($m in [regex]::Matches($t, '"((?:[^"\\]|\\.)*)"\s*(:)?')) {
      if ($m.Groups[2].Success) { continue }   # an object key such as "labels":
      $vals += $m.Groups[1].Value
    }
    return $vals
  }
  if ($t) { return @($t) }
  return @()
}

function Get-FgRunsOnInfo {
  # Collects the literal labels in a runs-on value. Outside ${{ }} every bare word is a
  # label (group:/labels: keys dropped); inside ${{ }} each 'quoted' literal is one, and
  # Fallback holds the labels of a trailing `|| '<literal>'` (or `|| fromJSON('<json>')`).
  param([string]$RunsOn)
  $info = [pscustomobject]@{ IsExpression = $false; Labels = @(); Fallback = @() }
  $text = [string]$RunsOn
  $exprs = [regex]::Matches($text, '\$\{\{(.*?)\}\}')
  if ($exprs.Count -gt 0) { $info.IsExpression = $true }
  $outside = [regex]::Replace($text, '\$\{\{.*?\}\}', ' ')
  $labels = @()
  foreach ($w in ($outside -split '[\s,\[\]\{\}]+')) {
    $w = $w.Trim().Trim('"', "'").Trim()
    if (-not $w -or $w -eq '-') { continue }
    if ($w -match '^(?i:group|labels):?$') { continue }
    $w = $w -replace '^(?i:group|labels):', ''
    if ($w -match ':$') { continue }
    if ($w) { $labels += $w }
  }
  foreach ($e in $exprs) {
    $body = $e.Groups[1].Value
    foreach ($q in [regex]::Matches($body, "'((?:[^']|'')*)'")) {
      $labels += @(Get-FgLiteralLabel ($q.Groups[1].Value -replace "''", "'"))
    }
  }
  $info.Labels = @($labels)
  if ($exprs.Count -eq 1 -and $outside.Trim() -eq '') {
    $fm = [regex]::Match($exprs[0].Groups[1].Value, "\|\|\s*(?:fromJSON\(\s*)?'((?:[^']|'')*)'\s*\)?\s*$")
    if ($fm.Success) { $info.Fallback = @(Get-FgLiteralLabel ($fm.Groups[1].Value -replace "''", "'")) }
  }
  return $info
}

function Test-FgLinuxLabelSet {
  # True when the labels name a Linux runner: at least one Linux label, the rest neutral.
  param([string[]]$Labels)
  $kinds = @($Labels | ForEach-Object { Get-FgLabelKind $_ })
  if ($kinds.Count -eq 0) { return $false }
  if (@($kinds | Where-Object { $_ -eq 'linux' }).Count -eq 0) { return $false }
  return (@($kinds | Where-Object { $_ -ne 'linux' -and $_ -ne 'neutral' }).Count -eq 0)
}

function Get-FgRunnerOs {
  # Classifies a job's runs-on text (inline value, list or group/labels mapping).
  # Literal labels: windows wins over linux if both appear. An expression is 'linux' only
  # when no literal in it names Windows or macOS and either its literal fallback
  # (`|| 'ubuntu-latest'`) or all of its literal labels name Linux; otherwise 'unknown'.
  # So ${{ matrix.runner }} or ${{ inputs.runner }} alone stay 'unknown' (Windows rule).
  param([string]$RunsOn)
  $info = Get-FgRunsOnInfo -RunsOn $RunsOn
  $kinds = @($info.Labels | ForEach-Object { Get-FgLabelKind $_ })
  $hasWin = @($kinds | Where-Object { $_ -eq 'windows' }).Count -gt 0
  $hasMac = @($kinds | Where-Object { $_ -eq 'macos' }).Count -gt 0
  $os = 'unknown'
  if ($info.IsExpression) {
    if (-not $hasWin -and -not $hasMac) {
      if ((Test-FgLinuxLabelSet $info.Fallback) -or (Test-FgLinuxLabelSet $info.Labels)) { $os = 'linux' }
    }
  } elseif ($hasWin) { $os = 'windows' }
  elseif (@($kinds | Where-Object { $_ -eq 'linux' }).Count -gt 0) { $os = 'linux' }
  elseif ($hasMac) { $os = 'macos' }
  return $os
}

function Test-FgPowerShellShell { param([string]$Shell) return ($Shell -match '^powershell(?:\s+.*\{0\}.*)?$') }

function Find-FgWorkflowShells {
  # Team rule (CI shells): every run step in a job on a Windows runner uses
  # Windows PowerShell 5.1 (`shell: powershell`), per step or through job/workflow
  # `defaults: run: shell:`. Jobs on Linux runners (ubuntu-*, a `linux` label) are skipped:
  # bash, sh and python are fine there. An expression runs-on counts as Linux when its
  # literal fallback or all of its literal labels name Linux and none names Windows (see
  # Get-FgRunnerOs). Anything else with neither a Windows nor a Linux label is checked as Windows.
  param([string]$Path, [string[]]$Lines)
  $out = New-Object System.Collections.Generic.List[object]
  $Lines = @($Lines | ForEach-Object { $_.TrimEnd("`r") })
  $wfShell = Get-FgDefaultShell -Lines $Lines -Start 0 -End $Lines.Count -KeyIndent 0
  $jobsAt = -1
  for ($i = 0; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match '^jobs\s*:') { $jobsAt = $i; break } }
  if ($jobsAt -lt 0) { return $out }
  # job keys: first indented key level under jobs:
  $jobIndent = -1; $jobStarts = @()
  for ($i = $jobsAt + 1; $i -lt $Lines.Count; $i++) {
    $l = $Lines[$i]
    if ($l -notmatch '\S' -or $l -match '^\s*#') { continue }
    $ind = Get-FgIndent $l
    if ($ind -eq 0) { break }
    if ($jobIndent -lt 0) { $jobIndent = $ind }
    if ($ind -eq $jobIndent -and $l -match '^\s*([A-Za-z0-9_-]+)\s*:') { $jobStarts += $i }
  }
  $jobEnd = $Lines.Count
  for ($i = $jobsAt + 1; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match '^\S' -and $Lines[$i] -notmatch '^#') { $jobEnd = $i; break } }
  for ($k = 0; $k -lt $jobStarts.Count; $k++) {
    $s = $jobStarts[$k]
    $e = $jobEnd; if ($k + 1 -lt $jobStarts.Count) { $e = $jobStarts[$k + 1] }
    $null = $Lines[$s] -match '^\s*([A-Za-z0-9_-]+)\s*:'; $job = $Matches[1]
    $keyInd = $jobIndent + 2
    for ($i = $s + 1; $i -lt $e; $i++) { if ($Lines[$i] -match '\S' -and $Lines[$i] -notmatch '^\s*#') { $keyInd = Get-FgIndent $Lines[$i]; break } }
    # runs-on (inline or list)
    $runsOn = ''; $isReusable = $false
    for ($i = $s + 1; $i -lt $e; $i++) {
      $l = $Lines[$i]
      if ((Get-FgIndent $l) -ne $keyInd) { continue }
      if ($l -match '^\s*uses\s*:') { $isReusable = $true }
      if ($l -match '^\s*runs-on\s*:\s*(.*)$') {
        $runsOn = Get-FgUncommentedText $Matches[1]
        if ($runsOn -match '^\s*$') {
          $runsOn = ''
          for ($j = $i + 1; $j -lt $e; $j++) {
            $m = $Lines[$j]
            if ($m -notmatch '\S' -or $m -match '^\s*#') { continue }
            if ((Get-FgIndent $m) -le $keyInd) { break }
            $runsOn += ' ' + (Get-FgUncommentedText $m).Trim()
          }
        }
      }
    }
    if ($isReusable) { continue }
    $os = Get-FgRunnerOs -RunsOn $runsOn; $osReported = $false
    $ro = $runsOn.Trim(); if (-not $ro) { $ro = '(none found)' }
    $jobShell = Get-FgDefaultShell -Lines $Lines -Start ($s + 1) -End $e -KeyIndent $keyInd
    # steps
    $stepsAt = -1
    for ($i = $s + 1; $i -lt $e; $i++) { if ($Lines[$i] -match '^\s*steps\s*:' -and (Get-FgIndent $Lines[$i]) -eq $keyInd) { $stepsAt = $i; break } }
    if ($stepsAt -lt 0) { continue }
    $dash = -1; $items = @()
    for ($i = $stepsAt + 1; $i -lt $e; $i++) {
      $l = $Lines[$i]
      if ($l -notmatch '\S' -or $l -match '^\s*#') { continue }
      $ind = Get-FgIndent $l
      if ($ind -le $keyInd -and $l -notmatch '^\s*-') { break }
      if ($l -match '^\s*-(\s|$)') {
        if ($dash -lt 0) { $dash = $ind }
        if ($ind -eq $dash) { $items += $i }
      }
    }
    for ($t = 0; $t -lt $items.Count; $t++) {
      $a = $items[$t]; $b = $e; if ($t + 1 -lt $items.Count) { $b = $items[$t + 1] }
      $stepKey = $dash + 2
      $runLine = 0; $stepShell = ''
      for ($i = $a; $i -lt $b; $i++) {
        $l = $Lines[$i]
        $isKey = ($i -eq $a) -or ((Get-FgIndent $l) -eq $stepKey)
        if (-not $isKey) { continue }
        $kl = $l; if ($i -eq $a) { $kl = $l -replace '^(\s*)-\s', '$1  ' }
        if ($kl -match '^\s*run\s*:') { $runLine = $i + 1 }
        if ($kl -match '^\s*shell\s*:\s*(.+?)\s*(?:#.*)?$') { $stepShell = $Matches[1].Trim('"', "'") }
      }
      if ($runLine -eq 0) { continue }
      $eff = $stepShell; $src = 'step'
      if (-not $eff) { $eff = $jobShell; $src = 'job defaults' }
      if (-not $eff) { $eff = $wfShell; $src = 'workflow defaults' }
      if ($os -eq 'linux') {
        # Linux runner: bash, sh, python and pwsh are all fine. `powershell` is Windows-only.
        if ($eff -and (Test-FgPowerShellShell $eff)) {
          $out.Add((New-FgFinding 'workflows' 'linux-powershell' 'WARN' $Path $runLine "shell: $eff" "job '$job' runs on a Linux runner ($ro), where shell: powershell (Windows PowerShell 5.1) does not exist; use bash, sh, python or pwsh there, and run 5.1 checks in a job on a Windows runner"))
        }
        continue
      }
      if ($os -eq 'macos') {
        if ($osReported) { continue }
        $osReported = $true
        $out.Add((New-FgFinding 'workflows' 'unsupported-runner' 'FAIL' $Path $runLine "runs-on: $ro" "job '$job' runs on macOS; the org runs CI on Windows runners (shell: powershell, Windows PowerShell 5.1) or Linux runners (bash, sh or python are fine)"))
        continue
      }
      $why = "job '$job' runs on a Windows runner"
      if ($os -eq 'unknown') { $why = "job '$job' has runs-on: $ro, which the gate can't tell is Linux, so the Windows rule applies (for a Linux job use a literal ubuntu-* or linux label, or a literal Linux fallback such as || 'ubuntu-latest')" }
      $tail = 'run steps on Windows runners must use shell: powershell (Windows PowerShell 5.1), per step or via defaults: run: shell: powershell; Linux runners may use bash, sh or python'
      if ($eff) {
        if (-not (Test-FgPowerShellShell $eff)) {
          $out.Add((New-FgFinding 'workflows' 'non-powershell-shell' 'FAIL' $Path $runLine "shell: $eff" "$why ($src); $tail"))
        }
      } elseif ($os -eq 'unknown' -and $ro -match '\$\{\{') {
        $out.Add((New-FgFinding 'workflows' 'missing-shell' 'WARN' $Path $runLine 'no shell:' "$why; without shell: powershell a Windows step runs in pwsh when it is installed, not Windows PowerShell 5.1; $tail"))
      } else {
        $out.Add((New-FgFinding 'workflows' 'missing-shell' 'FAIL' $Path $runLine 'no shell:' "$why; without shell: powershell the step runs in pwsh when it is installed, not Windows PowerShell 5.1; $tail"))
      }
    }
  }
  return $out
}

function Find-FgWorkflows {
  # ChangedPaths: repo paths changed in the PR. Every workflow gets the shell rule;
  # changed workflows also get the 8b danger scan.
  param([string]$RepoPath, [string[]]$ChangedPaths)
  $out = New-Object System.Collections.Generic.List[object]
  $dir = [System.IO.Path]::Combine($RepoPath, '.github', 'workflows')
  if (-not (Test-Path -LiteralPath $dir)) { return $out }
  foreach ($f in (Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Name -match '\.ya?ml$' } | Sort-Object Name)) {
    $rel = ".github/workflows/$($f.Name)"
    $lines = [System.IO.File]::ReadAllLines($f.FullName)
    foreach ($x in @(Find-FgWorkflowShells -Path $rel -Lines $lines)) { $out.Add($x) }
    if (@($ChangedPaths) -contains $rel) { foreach ($x in @(Find-FgWorkflowDanger -Path $rel -Lines $lines)) { $out.Add($x) } }
  }
  return $out
}
