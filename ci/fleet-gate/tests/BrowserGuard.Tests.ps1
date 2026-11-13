BeforeDiscovery {
  $wfFound = Test-Path -LiteralPath ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '..', '.github', 'workflows', 'fleet-gate.yml'))
}
BeforeAll {
  $root = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..'))
  Import-Module ([System.IO.Path]::Combine($root, 'browser', 'BrowserA11y.psm1')) -Force
  $repoRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($root, '..', '..'))
  $wf = [System.IO.Path]::Combine($repoRoot, '.github', 'workflows', 'fleet-gate.yml')
}

Describe 'Test-FgBrowserScanAllowed' {
  It 'allows a team member on a same-repo branch' {
    (Test-FgBrowserScanAllowed -EventName 'pull_request' -Author 'seakintruth' -HeadRepo 'org/r' -BaseRepo 'org/r' -HeadOwner 'org').Allowed | Should -BeTrue
  }
  It "allows a team member from the member's own fork" {
    (Test-FgBrowserScanAllowed -EventName 'pull_request' -Author 'BenKenBoy' -HeadRepo 'BenKenBoy/r' -BaseRepo 'org/r' -HeadOwner 'BenKenBoy').Allowed | Should -BeTrue
  }
  It "skips a team member's PR from someone else's fork" {
    (Test-FgBrowserScanAllowed -EventName 'pull_request' -Author 'cyprionceo' -HeadRepo 'stranger/r' -BaseRepo 'org/r' -HeadOwner 'stranger').Allowed | Should -BeFalse
  }
  It 'skips anyone not on the list' {
    (Test-FgBrowserScanAllowed -EventName 'pull_request' -Author 'stranger' -HeadRepo 'org/r' -BaseRepo 'org/r' -HeadOwner 'org').Allowed | Should -BeFalse
  }
  It 'compares logins case-insensitively, like GitHub expressions' {
    (Test-FgBrowserScanAllowed -EventName 'pull_request' -Author 'SeakinTruth' -HeadRepo 'org/r' -BaseRepo 'org/r' -HeadOwner 'org').Allowed | Should -BeTrue
  }
  It 'skips events other than pull_request (merge_group has no PR author)' {
    (Test-FgBrowserScanAllowed -EventName 'merge_group' -Author 'seakintruth' -HeadRepo 'org/r' -BaseRepo 'org/r' -HeadOwner 'org').Allowed | Should -BeFalse
  }
  It 'has exactly the six members' {
    @(Get-FgTeam).Count | Should -Be 6
  }
}

Describe 'workflow guard matches the script list' {
  It 'every fromJSON team list in fleet-gate.yml equals Get-FgTeam' -Skip:(-not $wfFound) {
    $text = [System.IO.File]::ReadAllText($wf)
    $lists = [regex]::Matches($text, "fromJSON\('(\[[^\]]*\])'\)")
    $lists.Count | Should -BeGreaterOrEqual 2
    foreach ($m in $lists) {
      $got = @(ConvertFrom-Json $m.Groups[1].Value) | Sort-Object
      $got -join ',' | Should -Be ((@(Get-FgTeam) | Sort-Object) -join ',')
    }
    $text | Should -Not -Match 'pull_request_target'
    $text | Should -Match 'github\.event\.pull_request\.head\.repo\.full_name == github\.repository'
    $text | Should -Match 'github\.event\.pull_request\.head\.repo\.owner\.login == github\.event\.pull_request\.user\.login'
  }
}

Describe 'Resolve-FgServePath' {
  It 'serves files under the root and refuses traversal' {
    $d = [System.IO.Path]::Combine($TestDrive, 'site'); $null = New-Item -ItemType Directory -Path $d -Force
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'index.html'), '<p>hi</p>')
    Resolve-FgServePath -Root $d -UrlPath '/' | Should -Not -BeNullOrEmpty
    Resolve-FgServePath -Root $d -UrlPath '/../secret.txt' | Should -BeNullOrEmpty
    Resolve-FgServePath -Root $d -UrlPath '/%2e%2e/secret.txt' | Should -BeNullOrEmpty
  }
}

Describe 'Get-FgPageList (.fleet-gate/pages.txt)' {
  BeforeAll {
    $repo = [System.IO.Path]::Combine($TestDrive, 'repo')
    $outside = [System.IO.Path]::Combine($TestDrive, 'outside')
    foreach ($d in @($repo, $outside, [System.IO.Path]::Combine($repo, 'web'), [System.IO.Path]::Combine($repo, '.fleet-gate'))) { $null = New-Item -ItemType Directory -Path $d -Force }
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($repo, 'web', 'index.html'), '<p>ok</p>')
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($outside, 'secret.html'), '<p>no</p>')
    $cfg = [System.IO.Path]::Combine($repo, '.fleet-gate', 'pages.txt')
    function Set-Pages([string[]]$Lines) { [System.IO.File]::WriteAllLines($cfg, $Lines) }
    function Get-Pages { @(Get-FgPageList -RepoPath $repo -WarningAction SilentlyContinue) }
    # Symlink / junction creation can need extra rights on Windows; tests skip when it fails.
    $script:fileLink = $null; $script:dirLink = $null
    try { $script:fileLink = New-Item -ItemType SymbolicLink -Path ([System.IO.Path]::Combine($repo, 'link.html')) -Target ([System.IO.Path]::Combine($outside, 'secret.html')) -ErrorAction Stop } catch { }
    $dirType = 'SymbolicLink'
    if ($PSVersionTable.PSVersion.Major -le 5 -or (Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)) { $dirType = 'Junction' }
    try { $script:dirLink = New-Item -ItemType $dirType -Path ([System.IO.Path]::Combine($repo, 'linked')) -Target $outside -ErrorAction Stop } catch { }
  }
  It 'keeps a normal repo-relative page, with either slash' {
    Set-Pages @('web/index.html', 'web\index.html', '# comment', '')
    Get-Pages | Should -Be @('web/index.html')
  }
  It 'rejects rooted and absolute paths' {
    Set-Pages @('/etc/passwd', '\web\index.html', 'C:\Windows\win.ini', 'C:web\index.html', '\\server\share\x.html', 'file:///etc/passwd', ([System.IO.Path]::Combine($repo, 'web', 'index.html')))
    @(Get-Pages).Count | Should -Be 0
    (Resolve-FgRepoFile -RepoPath $repo -Rel 'C:\Windows\win.ini').Reason | Should -Be 'rooted or absolute path'
  }
  It 'rejects entries that resolve outside the repo' {
    Set-Pages @('..\outside\secret.html', '../outside/secret.html', 'web/../../outside/secret.html')
    @(Get-Pages).Count | Should -Be 0
    (Resolve-FgRepoFile -RepoPath $repo -Rel 'web\..\..\outside\secret.html').Reason | Should -Be 'resolves outside the repo'
  }
  It 'normalizes a .. that stays inside the repo' {
    Set-Pages @('web/../web/index.html')
    Get-Pages | Should -Be @('web/index.html')
  }
  It 'skips a symlinked file' {
    if (-not $script:fileLink) { Set-ItResult -Skipped -Because 'cannot create symlinks here'; return }
    Set-Pages @('link.html')
    @(Get-Pages).Count | Should -Be 0
    (Resolve-FgRepoFile -RepoPath $repo -Rel 'link.html').Reason | Should -Be 'symlink or junction'
  }
  It 'skips a page under a symlinked or junction directory' {
    if (-not $script:dirLink) { Set-ItResult -Skipped -Because 'cannot create junctions or symlinks here'; return }
    Set-Pages @('linked/secret.html')
    @(Get-Pages).Count | Should -Be 0
    (Resolve-FgRepoFile -RepoPath $repo -Rel 'linked/secret.html').Reason | Should -Be 'symlink or junction'
  }
  It 'the static server refuses files behind a symlinked directory' {
    if (-not $script:dirLink) { Set-ItResult -Skipped -Because 'cannot create junctions or symlinks here'; return }
    Resolve-FgServePath -Root $repo -UrlPath '/linked/secret.html' | Should -BeNullOrEmpty
    Resolve-FgServePath -Root $repo -UrlPath '/web/index.html' | Should -Not -BeNullOrEmpty
  }
  It 'rejects missing files' {
    Set-Pages @('web/missing.html')
    @(Get-Pages).Count | Should -Be 0
  }
}

Describe 'Get-FgBrowserArgs (network lockdown)' {
  BeforeAll { $a = @(Get-FgBrowserArgs -ProfileDir 'p' -ServerPort 51234) }
  It 'sends all traffic to a dead loopback proxy' {
    $a | Should -Contain '--proxy-server=127.0.0.1:9'
  }
  It 'drops the implicit loopback bypass and bypasses only the scan server' {
    $a | Should -Contain '--proxy-bypass-list=<-loopback>;127.0.0.1:51234'
    @($a | Where-Object { $_ -like '--proxy-bypass-list=*' }).Count | Should -Be 1
  }
  It 'disables name resolution except for 127.0.0.1, and keeps DevTools on loopback' {
    $a | Should -Contain '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'
    $a | Should -Contain '--remote-debugging-address=127.0.0.1'
    @($a | Where-Object { $_ -match '^--(?:proxy-auto-detect|proxy-pac-url|no-proxy-server)' }).Count | Should -Be 0
  }
  It 'requires a server port' {
    { Get-FgBrowserArgs -ProfileDir 'p' -ServerPort 0 } | Should -Throw
  }
}
