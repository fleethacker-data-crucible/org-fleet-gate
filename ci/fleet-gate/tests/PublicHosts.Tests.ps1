BeforeAll { . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1')); $script:pub = @{ hosts = @('navy.mil'); secret = @('token','sig') } }
Describe 'public https host allowance' {
  It 'ignores an https doc link in markdown' {
    Test-FgPublicUrlMatch -Path 'docs/ROADMAP.md' -Match 'www.navy.mil' -LineText '- [x](https://www.navy.mil/Press-Office/a)' -Public $script:pub | Should -Be 'IGNORED'
  }
  It 'warns for the same URL in code' {
    Test-FgPublicUrlMatch -Path 'src/app.js' -Match 'www.navy.mil' -LineText "fetch('https://www.navy.mil/feed')" -Public $script:pub | Should -Be 'WARN'
  }
  It 'keeps FAIL for http, bare hosts, userinfo, secret queries and unlisted hosts' {
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'www.navy.mil' -LineText 'http://www.navy.mil/' -Public $script:pub | Should -BeNullOrEmpty
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'www.navy.mil' -LineText 'host = www.navy.mil' -Public $script:pub | Should -BeNullOrEmpty
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'www.navy.mil' -LineText 'https://u:p@www.navy.mil/' -Public $script:pub | Should -BeNullOrEmpty
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'www.navy.mil' -LineText 'https://www.navy.mil/x?token=abc' -Public $script:pub | Should -BeNullOrEmpty
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'portal.example.com' -LineText 'https://portal.example.com/' -Public $script:pub | Should -BeNullOrEmpty
    Test-FgPublicUrlMatch -Path 'a.md' -Match 'evilnavy.mil' -LineText 'https://evilnavy.mil/' -Public $script:pub | Should -BeNullOrEmpty
  }
}
