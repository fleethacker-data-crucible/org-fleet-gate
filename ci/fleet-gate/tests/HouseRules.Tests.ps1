BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Test-FgLicense' {
  It 'passes an MIT LICENSE and fails a missing one' {
    $d = [System.IO.Path]::Combine($TestDrive, 'lic'); $null = New-Item -ItemType Directory -Path $d -Force
    @(Test-FgLicense -RepoPath $d | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'LICENSE'), "MIT License`n`nPermission is hereby granted, free of charge, to any person`n")
    @(Test-FgLicense -RepoPath $d | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 0
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
  It 'ignores a comparison against 0.0.0.0 (netstat guard, not a bind)' {
    $files = @{
      'tools/fairlead-forward.mjs' = "if (host !== '127.0.0.1' && host !== '0.0.0.0' && host !== '[::1]') continue;"
      'src/g.js' = "if (host === '0.0.0.0') { return; }"
    }
    $r = @(Find-FgListeners -Files $files -Patterns $rows -Allow $null)
    @($r | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 0
  }
}
