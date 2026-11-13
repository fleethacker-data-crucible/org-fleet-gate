BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Find-FgSecurityChanges' {
  BeforeAll { $rows = @(Read-FgTsv (Get-FgDataPath 'security-paths.tsv') 3) }
  It 'routes auth paths and listener code to the Researcher as WARN' {
    $r = @(Find-FgSecurityChanges -ChangedPaths @('src/auth/Login.ps1', 'README.md') -AddedLines @(New-TestAdded 'src/Server.ps1' '$l = [System.Net.HttpListener]::new()') -Patterns $rows)
    @($r | Where-Object { $_.Severity -ne 'WARN' }).Count | Should -Be 0
    $s = Get-FgSecuritySummary -Findings $r
    $s | Should -Match 'auth'
    $s | Should -Match 'listeners'
  }
  It 'ignores prose in docs' {
    @(Find-FgSecurityChanges -ChangedPaths @('docs/guide.md') -AddedLines @(New-TestAdded 'docs/guide.md' 'Send the Authorization header') -Patterns $rows).Count | Should -Be 0
  }
}

Describe 'report' {
  It 'rolls the worst severity up per check' {
    $f = @((New-FgFinding 'house' 'license' 'FAIL' 'LICENSE' 0 'missing' 'x'), (New-FgFinding 'security' 'auth' 'WARN' 'a.ps1' 1 'm' 'n'))
    $rows = @(Get-FgSummaryRows -Findings $f -Errors @{})
    ($rows | Where-Object { $_.Check -eq 'house' }).Result | Should -Be 'FAIL'
    ($rows | Where-Object { $_.Check -eq 'security' }).Result | Should -Be 'WARN'
    ($rows | Where-Object { $_.Check -eq 'binaries' }).Result | Should -Be 'PASS'
    Get-FgWorstSeverity -Findings $f | Should -Be 'FAIL'
  }
}

Describe 'Invoke-FleetGate.ps1 end to end' {
  BeforeAll {
    $exe = (Get-Process -Id $PID).Path
    $script = [System.IO.Path]::Combine($script:FgRoot, 'Invoke-FleetGate.ps1')
  }
  It 'passes a clean change and fails a bad one' {
    $d = [System.IO.Path]::Combine($TestDrive, 'e2e'); New-TestRepo $d
    $base = @(Invoke-TestGit $d @('rev-parse', 'HEAD'))[0].Trim()
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'notes.md'), "hello`n")
    Invoke-TestGit $d @('add', '-A'); Invoke-TestGit $d @('commit', '-q', '-m', 'ok')
    $null = & $exe -NoProfile -File $script -RepoPath $d -BaseSha $base -SkipGitleaks -TempDir ([System.IO.Path]::Combine($TestDrive, 't1'))
    $LASTEXITCODE | Should -Be 0
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'cfg.ps1'), ("`$u = 'https://svc.agency." + 'm' + "il/'`n"))
    Invoke-TestGit $d @('add', '-A'); Invoke-TestGit $d @('commit', '-q', '-m', 'bad')
    $null = & $exe -NoProfile -File $script -RepoPath $d -BaseSha $base -SkipGitleaks -TempDir ([System.IO.Path]::Combine($TestDrive, 't2'))
    $LASTEXITCODE | Should -Be 1
  }
}
