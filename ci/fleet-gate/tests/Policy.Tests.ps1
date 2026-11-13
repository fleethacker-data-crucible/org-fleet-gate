BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Read-FgPolicyText' {
  It 'reads private-permanent with a trailing comment' {
    $p = Read-FgPolicyText "# c`nvisibility: private-permanent  # approved by the owner`n"
    $p.visibility | Should -Be 'private-permanent'
    @($p.errors).Count | Should -Be 0
  }
  It 'reports unknown keys and values' {
    $p = Read-FgPolicyText "visibility: secret`nmode: x"
    $p.visibility | Should -Be ''
    @($p.errors).Count | Should -Be 2
  }
  It 'is empty for no text' { (Read-FgPolicyText '').visibility | Should -Be '' }
}

Describe 'Resolve-FgPolicySeverity' {
  BeforeAll {
    $on = @{ visibility = 'private-permanent'; errors = @() }
    function Get-PolicyFinding {
      @(
        (New-FgFinding 'sensitive' 'private-ip' 'FAIL' 'docs/a.md' 3 ('10.' + '1.2.3') ''),
        (New-FgFinding 'sensitive' 'mil-host' 'FAIL' 'docs/a.md' 4 'h' ''),
        (New-FgFinding 'sensitive' 'gitleaks' 'FAIL' 'a.ps1' 5 'REDACTED' 'gitleaks generic-api-key'),
        (New-FgFinding 'sensitive' 'marking-distro' 'FAIL' 'docs/a.md' 6 'd' ''),
        (New-FgFinding 'house' 'listener-any-address' 'FAIL' 'a.ps1' 7 'Any' '')
      )
    }
  }
  It 'downgrades only publication-only kinds to WARN with a note' {
    $r = @(Resolve-FgPolicySeverity -Findings (Get-PolicyFinding) -Policy $on)
    ($r | Where-Object Kind -eq 'private-ip').Severity | Should -Be 'WARN'
    ($r | Where-Object Kind -eq 'private-ip').Note | Should -Match 'private-permanent'
    foreach ($k in 'mil-host', 'gitleaks', 'marking-distro', 'listener-any-address') { ($r | Where-Object Kind -eq $k).Severity | Should -Be 'FAIL' }
  }
  It 'changes nothing without the policy' {
    $r = @(Resolve-FgPolicySeverity -Findings (Get-PolicyFinding) -Policy (Read-FgPolicyText ''))
    @($r | Where-Object Severity -eq 'FAIL').Count | Should -Be 5
  }
  It 'FAILs when the repo is public' {
    $r = @(Resolve-FgPolicySeverity -Findings @() -Policy $on -Visibility 'public')
    $r[0].Kind | Should -Be 'policy-public'; $r[0].Severity | Should -Be 'FAIL'
  }
  It 'adds nothing when visibility is private or unknown' {
    @(Resolve-FgPolicySeverity -Findings @() -Policy $on -Visibility 'private').Count | Should -Be 0
    @(Resolve-FgPolicySeverity -Findings @() -Policy $on -Visibility '').Count | Should -Be 0
  }
}

Describe 'Get-FgRepoVisibility' {
  It 'reads visibility and the private flag, else unknown' {
    $f = Join-Path $TestDrive 'ev.json'
    [System.IO.File]::WriteAllText($f, '{"repository":{"private":false,"visibility":"public"}}'); Get-FgRepoVisibility -EventPath $f | Should -Be 'public'
    [System.IO.File]::WriteAllText($f, '{"repository":{"private":true}}'); Get-FgRepoVisibility -EventPath $f | Should -Be 'private'
    [System.IO.File]::WriteAllText($f, '{"action":"x"}'); Get-FgRepoVisibility -EventPath $f | Should -Be ''
    Get-FgRepoVisibility -EventPath (Join-Path $TestDrive 'none.json') | Should -Be ''
  }
}

Describe 'Get-FgPolicy' {
  It 'reads the base commit, not the head' {
    $d = Join-Path $TestDrive 'repo'; New-TestRepo $d
    $base = (Invoke-TestGit $d @('rev-parse', 'HEAD')).Trim()
    $null = New-Item -ItemType Directory -Path (Join-Path $d '.fleet-gate') -Force
    [System.IO.File]::WriteAllText((Join-Path $d '.fleet-gate\policy.txt'), "visibility: private-permanent`n")
    Invoke-TestGit $d @('add', '-A'); Invoke-TestGit $d @('commit', '-q', '-m', 'head turns it on')
    $head = (Invoke-TestGit $d @('rev-parse', 'HEAD')).Trim()
    (Get-FgPolicy -RepoPath $d -BaseRef $base).visibility | Should -Be ''
    (Get-FgPolicy -RepoPath $d -BaseRef $head).visibility | Should -Be 'private-permanent'
    (Get-FgPolicy -RepoPath $d).visibility | Should -Be 'private-permanent'
    (Get-FgPolicy -RepoPath $d -BaseRef $head -PolicyPath (Join-Path $TestDrive 'missing.txt')).visibility | Should -Be ''
  }
}

Describe 'retired allowlist kind' {
  It 'ignores retired names only under the listed path' {
    $allow = Read-FgAllowlist -Paths @()
    $allow.retired = @('^scripts/muse/')
    $rows = Get-TestRows 'retired-names.tsv'
    $name = 'C' + 'ascade'
    $r = @(Find-FgRetiredNames -AddedLines @((New-TestAdded 'scripts/muse/a.md' "uses $name"), (New-TestAdded 'docs/b.md' "uses $name")) -Patterns $rows -Allow $allow)
    ($r | Where-Object Path -eq 'scripts/muse/a.md').Severity | Should -Be 'IGNORED'
    ($r | Where-Object Path -eq 'docs/b.md').Severity | Should -Be 'FAIL'
  }
  It 'does not ignore sensitive content under that path' {
    $allow = Read-FgAllowlist -Paths @(); $allow.retired = @('^scripts/muse/')
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'scripts/muse/a.ps1' ('h = ''portal.agency.' + 'm' + 'il''')) -Patterns (Get-TestRows 'sensitive-patterns.tsv') -Allow $allow)
    $r[0].Severity | Should -Be 'FAIL'
  }
}