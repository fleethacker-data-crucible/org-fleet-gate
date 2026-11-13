BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Test-FgLicense' {
  It 'passes an MIT LICENSE and fails a missing one' {
    $d = [System.IO.Path]::Combine($TestDrive, 'lic'); $null = New-Item -ItemType Directory -Path $d -Force
    @(Test-FgLicense -RepoPath $d | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'LICENSE'), "MIT License`n`nPermission is hereby granted, free of charge, to any person`n")
    @(Test-FgLicense -RepoPath $d | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 0
  }
}

Describe 'Find-FgRetiredNames' {
  BeforeAll { $rows = Get-TestRows 'retired-names.tsv'; $old = 'C' + 'ascade' }
  It 'fails a retired name in an added line, once per line' {
    $r = @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'README.md' "Run $old and $old again") -Patterns $rows -Allow $null)
    $r.Count | Should -Be 1
    $r[0].Severity | Should -Be 'FAIL'
  }
  It 'does not flag SQL ON DELETE clauses or geometry words' {
    $sql = 'FOREIGN KEY (a) REFERENCES b(id) ON DELETE ' + $old.ToUpper()
    @(Find-FgRetiredNames -AddedLines @((New-TestAdded 'db.sql' $sql), (New-TestAdded 'g.js' 'ctx.arc(0, 0, r, 0, 2 * Math.PI)')) -Patterns $rows -Allow $null | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 0
  }
  It 'accepts the compatibility header but still finds a retired name later on the line' {
    $name = 'A' + 'RC'
    $header = '{"X-' + $name + '-Client":"arc-ui/1"}'
    @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'ui/dist/prefs.js' $header) -Patterns $rows -Allow $null).Count | Should -Be 0
    $r = @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'ui/dist/prefs.js' ($header + '; label="Run ' + $name + '"')) -Patterns $rows -Allow $null)
    $r.Count | Should -Be 1
    $r[0].Severity | Should -Be 'FAIL'
  }
  It 'accepts geometric exports only inside an ECharts bundle' {
    $name = 'A' + 'rc'
    $line = 'var shapes={' + $name + ':()=>shape,BezierCurve:()=>curve}'
    @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'ui/dist/assets/echarts-hash.js' $line) -Patterns $rows -Allow $null).Count | Should -Be 0
    $label = 'var name=curve?' + [char]96 + $name + [char]96 + ':' + [char]96 + 'Angle' + [char]96
    @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'ui/dist/assets/echarts-hash.js' $label) -Patterns $rows -Allow $null).Count | Should -Be 0
    @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'src/app.js' $line) -Patterns $rows -Allow $null).Count | Should -Be 1
    @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'ui/dist/assets/echarts-hash.js' ('label="Run ' + $name + '"')) -Patterns $rows -Allow $null).Count | Should -Be 1
  }
}

Describe 'Find-FgListeners' {
  BeforeAll { $rows = Get-TestRows 'listener-patterns.tsv' }
  It 'fails any-address and port-only binds, passes loopback' {
    $files = @{
      'src/a.ps1' = '$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 8080)'
      'src/b.js'  = 'server.listen(8080);'
      'src/c.ps1' = '$l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8080)'
      'src/d.js'  = "server.listen(8080, '127.0.0.1');"
    }
    $r = @(Find-FgListeners -Files $files -Patterns $rows -Allow $null | Where-Object { $_.Severity -eq 'FAIL' })
    @($r | ForEach-Object { $_.Path } | Sort-Object -Unique) | Should -Be @('src/a.ps1', 'src/b.js')
  }
  It 'skips comment lines and softens fixtures to WARN' {
    $files = @{ 'src/e.ps1' = '# [System.Net.IPAddress]::Any is not allowed'; 'tests/fixtures/f.ps1' = '[System.Net.IPAddress]::Any' }
    $r = @(Find-FgListeners -Files $files -Patterns $rows -Allow $null)
    @($r | Where-Object { $_.Path -eq 'src/e.ps1' }).Count | Should -Be 0
    ($r | Where-Object { $_.Path -like 'tests/*' })[0].Severity | Should -Be 'WARN'
  }
}

Describe 'Retired names inside identifiers' {
  BeforeAll {
    $rows = Get-TestRows 'retired-names.tsv'
    $a = 'A' + 'RC'; $m = 'A' + 'rc'; $c = 'C' + 'ASCADE'; $k = 'KEY' + 'STONE'; $g = 'GEN' + 'AI'
    $bad = @(
      "`$env:${a}_PATH", "`$env:${a}_ROOT", "Get-${m}Secret", "Unlock-${m}VaultInteractive", "Find-${m}Root",
      "${c}_${a}_ITEM_GitLab", "${k}_${a}_PATH", "${g}_TOKEN", ('gen' + 'api'), ('Mail' + 'Hawk'), ('git' + 'mil'), ('adv' + 'ana-api')
    )
    $fine = @('arcTo(1)', 'Arcade', 'searchArchive', ('ON DELETE ' + $c), 'drawArc', 'ctx.arc(0, 0, r, 0, 2)', 'SEARCH_ARCHIVE', 'ArcTangent')
  }
  It 'fails each retired name written as part of an identifier' {
    foreach ($t in $bad) {
      $r = @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'src/app.ps1' $t) -Patterns $rows -Allow $null | Where-Object { $_.Severity -eq 'FAIL' })
      if ($r.Count -ne 1) { throw "not flagged: $t" }
    }
  }
  It 'leaves ordinary words that only look similar alone' {
    foreach ($t in $fine) {
      $r = @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'src/app.js' $t) -Patterns $rows -Allow $null | Where-Object { $_.Severity -eq 'FAIL' })
      if ($r.Count -ne 0) { throw "wrongly flagged: $t" }
    }
  }
  It 'fails the compatibility-alias phrase' {
    $r = @(Find-FgRetiredNames -AddedLines @(New-TestAdded 'docs/x.md' ('Keep a leg' + 'acy al' + 'ias for this.')) -Patterns $rows -Allow $null)
    $r.Count | Should -Be 1
    $r[0].Severity | Should -Be 'FAIL'
  }
  It 'does not flag its own data file' {
    $own = [System.IO.File]::ReadAllLines((Get-FgDataPath 'retired-names.tsv')) | Where-Object { $_ -notmatch '^\s*#' } | Where-Object { $_ }
    $added = @($own | ForEach-Object { New-TestAdded 'ci/fleet-gate/data/retired-names.tsv' $_ })
    @(Find-FgRetiredNames -AddedLines $added -Patterns $rows -Allow $null).Count | Should -Be 0
  }
}

Describe 'Find-FgRetiredNamesRepo' {
  BeforeAll {
    $rows = Get-TestRows 'retired-names.tsv'
    $script:Repo = [System.IO.Path]::Combine($TestDrive, 'scan')
    New-TestRepo $script:Repo
    $name = 'CASC' + 'ADE_' + 'ITEM'
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($script:Repo, 'app.ps1'), "ok`n`$x = `$env:$name`n")
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($script:Repo, 'CHANGELOG.md'), "$name was removed`n")
    $null = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine($script:Repo, 'docs/reports')) -Force
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($script:Repo, 'docs/reports/r.md'), "$name`n")
    Invoke-TestGit $script:Repo @('add', '-A'); Invoke-TestGit $script:Repo @('commit', '-q', '-m', 'files')
  }
  It 'reports a hit in an existing file at the configured severity and skips changelog and reports' {
    $w = @(Find-FgRetiredNamesRepo -RepoPath $script:Repo -Patterns $rows -Allow $null)
    $w.Count | Should -Be 1
    $w[0].Path | Should -Be 'app.ps1'
    $w[0].Line | Should -Be 2
    $w[0].Severity | Should -Be 'WARN'
    $w[0].Kind | Should -Be 'retired-name-repo'
    $f = @(Find-FgRetiredNamesRepo -RepoPath $script:Repo -Patterns $rows -Allow $null -Severity 'FAIL')
    $f[0].Severity | Should -Be 'FAIL'
  }
  It 'honours the allowlist' {
    $allow = [pscustomobject]@{ path = @('^app\.ps1$'); match = @(); line = @() }
    @(Find-FgRetiredNamesRepo -RepoPath $script:Repo -Patterns $rows -Allow $allow | Where-Object { $_.Severity -ne 'IGNORED' }).Count | Should -Be 0
  }
  It 'reads the severity from the setting file and defaults to WARN' {
    Get-FgRepoScanSeverity (Get-FgDataPath 'retired-names-repo.setting') | Should -Be 'WARN'
    $p = [System.IO.Path]::Combine($TestDrive, 's.setting')
    [System.IO.File]::WriteAllText($p, "# c`nFAIL`n"); Get-FgRepoScanSeverity $p | Should -Be 'FAIL'
    [System.IO.File]::WriteAllText($p, "nonsense`n"); Get-FgRepoScanSeverity $p | Should -Be 'WARN'
    Get-FgRepoScanSeverity ([System.IO.Path]::Combine($TestDrive, 'missing')) | Should -Be 'WARN'
  }
}
