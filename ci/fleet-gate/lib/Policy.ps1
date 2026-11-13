# Repo policy: .fleet-gate/policy.txt. "visibility: private-permanent" (owner-approved) turns the
# publication-only rules (content that matters only if the repo goes public) from FAIL into WARN.
# Read from the PR base commit, never the head, so a PR can't switch it on for itself.
# Secrets/gitleaks, military hosts, markings, distribution statements, endpoints, workflows,
# binaries, listeners and security routing are never changed by it.

$script:FgPublicationKinds = @('private-ip', 'internal-host', 'private-path', 'personal-email')
$script:FgPolicyNote = 'publication-only rule; repo is private-permanent (.fleet-gate/policy.txt)'

function Read-FgPolicyText {
  # Returns @{ visibility = ''|'private-permanent'|'default'; errors = @() }.
  param([string]$Text)
  $p = @{ visibility = ''; errors = @() }
  if ([string]::IsNullOrEmpty($Text)) { return $p }
  foreach ($l in ($Text -split "`n")) {
    $t = $l.TrimEnd("`r") -replace '\s+#.*$', ''
    if ($t -match '^\s*(#|$)') { continue }
    if ($t -match '^\s*([a-z-]+)\s*:\s*(\S+)\s*$') {
      $k = $Matches[1]; $v = $Matches[2]
      if ($k -ne 'visibility') { $p.errors += "unknown policy key '$k'"; continue }
      if ($v -eq 'private-permanent' -or $v -eq 'default') { $p.visibility = $v } else { $p.errors += "unknown visibility '$v'" }
    } else { $p.errors += "bad policy line '$($t.Trim())'" }
  }
  return $p
}

function Get-FgPolicy {
  # PolicyPath (a base-commit copy made by the caller) wins. Otherwise read the file at BaseRef;
  # with no BaseRef (full scan) read the working tree.
  param([string]$RepoPath, [string]$BaseRef = '', [string]$PolicyPath = '')
  if ($PolicyPath) {
    if (Test-Path -LiteralPath $PolicyPath -PathType Leaf) { return (Read-FgPolicyText ([System.IO.File]::ReadAllText($PolicyPath))) }
    return (Read-FgPolicyText '')
  }
  if ($BaseRef) {
    $lines = @(Invoke-FgGit -RepoPath $RepoPath -GitArgs @('show', ($BaseRef + ':.fleet-gate/policy.txt')) -AllowFail)
    return (Read-FgPolicyText ($lines -join "`n"))
  }
  $f = [System.IO.Path]::Combine($RepoPath, '.fleet-gate', 'policy.txt')
  if (Test-Path -LiteralPath $f -PathType Leaf) { return (Read-FgPolicyText ([System.IO.File]::ReadAllText($f))) }
  return (Read-FgPolicyText '')
}

function Get-FgRepoVisibility {
  # 'public', 'private' or '' (unknown) from the GitHub Actions event payload.
  param([string]$EventPath = $env:GITHUB_EVENT_PATH)
  if ([string]::IsNullOrEmpty($EventPath) -or -not (Test-Path -LiteralPath $EventPath -PathType Leaf)) { return '' }
  try { $e = ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($EventPath)) } catch { return '' }
  $r = $e.repository
  if ($null -eq $r) { return '' }
  $v = [string]$r.visibility
  if ($v) { if ($v -eq 'public') { return 'public' } else { return 'private' } }
  if ($null -ne $r.private) { if ([bool]$r.private) { return 'private' } else { return 'public' } }
  return ''
}

function Resolve-FgPolicySeverity {
  # Applies the repo policy to the findings. A private-permanent repo that is public FAILs.
  param([object[]]$Findings, $Policy, [string]$Visibility = '')
  $out = New-Object System.Collections.Generic.List[object]
  $on = ($null -ne $Policy -and $Policy.visibility -eq 'private-permanent')
  foreach ($f in @($Findings)) {
    if ($null -eq $f) { continue }
    if ($on -and $f.Check -eq 'sensitive' -and ($script:FgPublicationKinds -contains $f.Kind) -and $f.Severity -eq 'FAIL') {
      $f.Severity = 'WARN'
      $f.Note = (@($f.Note, $script:FgPolicyNote) | Where-Object { $_ }) -join '; '
    }
    $out.Add($f)
  }
  if ($on -and $Visibility -eq 'public') {
    $out.Add((New-FgFinding 'house' 'policy-public' 'FAIL' '.fleet-gate/policy.txt' 0 'private-permanent' 'the repo is public but its policy says private-permanent; make it private or remove the setting'))
  }
  return $out
}