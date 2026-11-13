BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')) }

Describe 'Test-FgBinaryFile' {
  BeforeAll { $ext = Read-FgBinaryExtensions (Get-FgDataPath 'binary-extensions.txt'); $text = [System.Text.Encoding]::ASCII.GetBytes('hello world') }
  It 'fails a new file over the size limit and points at Release assets' {
    $r = @(Test-FgBinaryFile -Path 'assets/big.dat' -Status 'A' -Size (6MB) -Head $text -BinaryExt $ext -Allow $null)
    $r[0].Severity | Should -Be 'FAIL'
  }
  It 'warns on a modified large file' {
    $r = @(Test-FgBinaryFile -Path 'data/big.csv' -Status 'M' -Size (6MB) -Head $text -BinaryExt $ext -Allow $null)
    $r[0].Severity | Should -Be 'WARN'
  }
  It 'fails model, WASM and archive extensions' {
    foreach ($p in 'assets/models/voice.onnx', 'web/app.wasm', 'dist/pkg.zip', 'tools/x.exe') {
      @(Test-FgBinaryFile -Path $p -Status 'A' -Size 100 -Head $text -BinaryExt $ext -Allow $null)[0].Severity | Should -Be 'FAIL'
    }
  }
  It 'fails executable magic bytes whatever the name' {
    $mz = [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00)
    @(Test-FgBinaryFile -Path 'notes.txt' -Status 'A' -Size 6 -Head $mz -BinaryExt $ext -Allow $null)[0].Severity | Should -Be 'FAIL'
  }
  It 'passes a small text file' {
    @(Test-FgBinaryFile -Path 'README.md' -Status 'A' -Size 11 -Head $text -BinaryExt $ext -Allow $null | Where-Object { $_.Severity -ne 'IGNORED' }).Count | Should -Be 0
  }
  It 'turns FAIL into WARN for an allowlisted path' {
    $allow = @{ path = @('^assets/icons/'); match = @(); line = @(); rule = @(); fingerprint = @(); errors = @() }
    @(Test-FgBinaryFile -Path 'assets/icons/app.ico.zip' -Status 'A' -Size 100 -Head $text -BinaryExt $ext -Allow $allow)[0].Severity | Should -Be 'WARN'
  }
  It 'help text names Release assets on vN.N.0 and the talkforge example' {
    $FgLargeAssetHelp | Should -Match 'vN\.N\.0'
    $FgLargeAssetHelp | Should -Match ([regex]::Escape('https://github.com/fleethacker-data-crucible/talkforge/blob/main/.github/workflows/release.yml'))
  }
}

Describe 'Find-FgBinaries (git)' {
  It 'flags a committed WASM file and ignores text' {
    $d = [System.IO.Path]::Combine($TestDrive, 'binrepo'); New-TestRepo $d
    $base = @(Invoke-TestGit $d @('rev-parse', 'HEAD'))[0].Trim()
    [System.IO.File]::WriteAllBytes([System.IO.Path]::Combine($d, 'app.wasm'), [byte[]](0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00))
    [System.IO.File]::WriteAllText([System.IO.Path]::Combine($d, 'notes.md'), "hello`n")
    Invoke-TestGit $d @('add', '-A'); Invoke-TestGit $d @('commit', '-q', '-m', 'add')
    $r = @(Find-FgBinaries -RepoPath $d -BaseSha $base -BinaryExt (Read-FgBinaryExtensions (Get-FgDataPath 'binary-extensions.txt')) -Allow $null | Where-Object { $_.Severity -ne 'IGNORED' })
    @($r | Where-Object { $_.Path -eq 'app.wasm' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    @($r | Where-Object { $_.Path -eq 'notes.md' }).Count | Should -Be 0
  }
}
