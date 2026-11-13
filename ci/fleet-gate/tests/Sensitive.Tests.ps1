BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Find-FgSensitiveAdded' {
  BeforeAll {
    $rows = Get-TestRows 'sensitive-patterns.tsv'
    # Built at runtime so this file holds no real-looking value.
    $milHost = 'portal.agency.' + 'm' + 'il'
    $marking = 'F' + 'OUO'
  }
  It 'fails a military host in an added line' {
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/app.ps1' "Uri = 'https://$milHost/api'") -Patterns $rows -Allow $null)
    ($r | Where-Object { $_.Kind -eq 'mil-host' }).Severity | Should -Be 'FAIL'
  }
  It 'fails a handling marking' {
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'docs/x.md' "Marked $marking here") -Patterns $rows -Allow $null)
    $r[0].Severity | Should -Be 'FAIL'
  }
  It 'downgrades to WARN under a test path' {
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'tests/x.Tests.ps1' "h = '$milHost'") -Patterns $rows -Allow $null)
    $r[0].Severity | Should -Be 'WARN'
  }
  It 'ignores obvious fakes' {
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/a.ps1' ('h = example.' + 'm' + 'il')) -Patterns $rows -Allow $null | Where-Object { $_.Severity -ne 'IGNORED' })
    $r.Count | Should -Be 0
  }
  It 'fails a private address, warns on a CIDR, skips impossible octets' {
    $ip = '10.' + '1.2.3'
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/a.ps1' "ip = '$ip'") -Patterns $rows -Allow $null)
    $r[0].Severity | Should -Be 'FAIL'
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/a.ps1' ("net = '" + '10.' + "0.0.0/8'")) -Patterns $rows -Allow $null)
    $r[0].Severity | Should -Be 'WARN'
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/a.ps1' ('v = ' + '10.' + '300.1.1')) -Patterns $rows -Allow $null | Where-Object { $_.Severity -ne 'IGNORED' })
    $r.Count | Should -Be 0
  }
  It 'honors an allowlist match entry' {
    $f = [System.IO.Path]::Combine($TestDrive, 'allow.txt')
    [System.IO.File]::WriteAllText($f, "# comment`nmatch:^portal\.agency\.  # reviewed`n")
    $allow = Read-FgAllowlist -Paths @($f)
    $r = @(Find-FgSensitiveAdded -AddedLines @(New-TestAdded 'src/a.ps1' "h = '$milHost'") -Patterns $rows -Allow $allow)
    $r[0].Severity | Should -Be 'IGNORED'
  }
}

Describe 'Find-FgEndpoints' {
  BeforeAll { $rows = Get-TestRows 'endpoint-patterns.tsv' }
  It 'fails a default endpoint outside fixtures and only warns inside them' {
    $h = 'https://api.service.' + 'm' + 'il/v1'
    $files = @{ 'src/config.ps1' = "`$Default = '$h'"; 'tests/fixtures/config.ps1' = "`$Default = '$h'" }
    $r = @(Find-FgEndpoints -Files $files -Patterns $rows -Allow $null)
    ($r | Where-Object { $_.Path -eq 'src/config.ps1' })[0].Severity | Should -Be 'FAIL'
    @($r | Where-Object { $_.Path -like 'tests/*' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 0
  }
}

Describe 'ConvertFrom-FgGitleaksReport' {
  It 'fails a redacted finding and honors an allowlisted rule' {
    $json = '[{"RuleID":"github-pat","File":"cfg.ps1","StartLine":1,"Match":"t = \"REDACTED\"","Secret":"REDACTED","Commit":"0123456789abcdef","Fingerprint":"0123456789abcdef:cfg.ps1:github-pat:1"}]'
    @(ConvertFrom-FgGitleaksReport -Json $json -Allow $null)[0].Severity | Should -Be 'FAIL'
    $allow = @{ path = @(); match = @(); line = @(); rule = @('^github-pat$'); fingerprint = @(); errors = @() }
    @(ConvertFrom-FgGitleaksReport -Json $json -Allow $allow)[0].Severity | Should -Be 'IGNORED'
  }
}

Describe 'gitleaks pin' {
  It 'pins a version and 64-hex SHA256 values' {
    InModuleScope FleetGate {
      $script:FgGitleaks.Version | Should -Match '^\d+\.\d+\.\d+$'
      $script:FgGitleaks.Windows.Sha256 | Should -Match '^[0-9a-f]{64}$'
      $script:FgGitleaks.Windows.Url | Should -Match ('/v' + [regex]::Escape($script:FgGitleaks.Version) + '/')
    }
  }
}
