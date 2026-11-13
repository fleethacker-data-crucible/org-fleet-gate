BeforeAll {
  . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1'))
  function Get-FixtureModel {
    $dir = [System.IO.Path]::Combine($script:Fx, 'contrast')
    $rules = @()
    foreach ($f in 'tokens.css', 'style.css') { $rules += @(ConvertFrom-FgCss -Text ([System.IO.File]::ReadAllText([System.IO.Path]::Combine($dir, $f))) -File "web/$f") }
    $nodes = @(ConvertFrom-FgHtml -Text ([System.IO.File]::ReadAllText([System.IO.Path]::Combine($dir, 'index.html'))) -File 'web/index.html')
    return @{ Rules = $rules; Nodes = $nodes }
  }
}

Describe 'contrast math' {
  It 'computes WCAG ratios' {
    [math]::Round((Get-FgContrastRatio (ConvertFrom-FgCssColor '#000') (ConvertFrom-FgCssColor '#fff')), 2) | Should -Be 21
    [math]::Round((Get-FgContrastRatio (ConvertFrom-FgCssColor '#8a6b45') (ConvertFrom-FgCssColor '#f3efe2')), 2) | Should -Be 4.28
    [math]::Round((Get-FgContrastRatio (ConvertFrom-FgCssColor 'rgb(138, 107, 69)') (ConvertFrom-FgCssColor 'white')), 2) | Should -Be 4.92
  }
  It 'resolves nested var() with fallbacks' {
    Resolve-FgCssVars -Value 'var(--a, var(--b, #123456))' -Vars @{} -Local @{} | Should -Be '#123456'
    Resolve-FgCssVars -Value 'var(--a)' -Vars @{ '--a' = 'var(--b)'; '--b' = '#abcdef' } -Local @{} | Should -Be '#abcdef'
  }
}

Describe 'Find-FgContrast' {
  It 'does not choose a different body class as the dynamic page background' {
    $rules = @(ConvertFrom-FgCss -Text 'body{background:#fff}body.console{background:#000}.dynamic{color:#000}' -File 'style.css')
    $nodes = @(ConvertFrom-FgHtml -Text '<html><body><main>Dashboard</main></body></html>' -File 'index.html')
    @(Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }
  It 'keeps a more specific page background even when the generic body rule comes later' {
    $rules = @(ConvertFrom-FgCss -Text 'body.app{background:#000}body{background:#fff}.dynamic{color:#fff}' -File 'style.css')
    $nodes = @(ConvertFrom-FgHtml -Text '<html><body class="app"></body></html>' -File 'index.html')
    @(Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }

  It 'applies the active theme color to dynamic elements absent from initial HTML' {
    $css = ':root{--bg:#111}html.light{--bg:#fff}body{background:var(--bg)}.dynamic{color:#fff}html.light .dynamic{color:#111}'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
    $bad = @(ConvertFrom-FgCss -Text ($css.Replace('html.light .dynamic{color:#111}', 'html.light .dynamic{color:#eee}')) -File 'style.css')
    @(Find-FgContrast -Rules $bad -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 1
  }
  It 'uses the winning themed ancestor background for dynamic controls' {
    $css = ':root{--bg:#111}html.light{--bg:#fff}body{background:var(--bg)}#side{background:#222}:root.grid #side{background:rgba(32,32,32,.45)}:root.light.grid #side{background:#eee}#side .dynamic{color:#aaa}:root.light #side .dynamic{color:#333}'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }
  It 'preserves selector specificity when choosing dynamic backgrounds and foregrounds' {
    $css = 'body{background:#fff}#panel{background:#000}.panel{background:#fff}#panel .text{color:#fff}.panel .text{color:#000}'
    $nodes = @(ConvertFrom-FgHtml -Text '<html><body><section id="panel" class="panel"><span class="text">Readable</span></section></body></html>' -File 'index.html')
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    @(Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }
  It 'counts root qualifier specificity rather than assuming a later skin rule wins' {
    $css = ':root{--bg:#fff}:root.light{--bg:#fff}body{background:var(--bg)}:root.light .text{color:#eee}html[data-skin="fleet"] .text{color:#000}'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    $r = @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL')
    @($r | Where-Object Note -Match 'skin fleet').Count | Should -Be 1
  }
  It 'composites a transparent control over its actual ancestor background' {
    $rules = @(ConvertFrom-FgCss -Text 'body{background:#fff}#panel{background:#000}#panel .text{background:rgba(255,255,255,.1);color:#fff}' -File 'style.css')
    @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
    $none = @(ConvertFrom-FgCss -Text 'body{background:#fff}#panel{background:#000}#panel .text{background:none;color:#fff}' -File 'style.css')
    @(Find-FgContrast -Rules $none -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }

  It 'distinguishes a direct child from a deeper span inside a button' {
    $css = 'body{background:#000;color:#fff}.footer > span{color:#aaa}.primary{background:#fff;color:#000}'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    $nodes = @(ConvertFrom-FgHtml -Text '<html><body><div class="footer"><span>status</span><button class="primary"><span>action</span></button></div></body></html>' -File 'index.html')
    @(Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
    $bad = @(ConvertFrom-FgCss -Text ($css.Replace('color:#aaa','color:#222')) -File 'style.css')
    @(Find-FgContrast -Rules $bad -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 1
  }
  It 'tests root light classes separately and applies the active color override' {
    $css = ':root { --bg:#000; } html.light { --bg:#fff; } body { background:var(--bg); } .text {color:#fff;} html.light .text {color:#000;}'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    $nodes = @(ConvertFrom-FgHtml -Text '<html><body><p class="text">readable</p></body></html>' -File 'index.html')
    @(Find-FgContrast -Rules $rules -Nodes $nodes -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
  }
  It 'keeps skin variables separate and still fails a genuinely low-contrast skin' {
    $css = ':root { --bg:#fff; --fg:#111; } :root[data-skin="night"] { --bg:#111; --fg:#222; } body { background:var(--bg); color:var(--fg); }'
    $rules = @(ConvertFrom-FgCss -Text $css -File 'style.css')
    $r = @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL')
    $r.Count | Should -Be 1
    $r[0].Note | Should -Match 'skin night'
  }
  It 'does not contrast-test invisible glyphs but still checks partially transparent visible text' {
    $rules = @(ConvertFrom-FgCss -Text 'body{background:#fff}.backing{color:transparent}.faded{color:rgba(0,0,0,.1)}' -File 'style.css')
    $r = @(Find-FgContrast -Rules $rules -Nodes @() -ChangedPaths @('style.css') | Where-Object Severity -eq 'FAIL')
    $r.Count | Should -Be 1
    $r[0].Note | Should -Match '\.faded'
  }
  It 'finds the brass label on the light sidebar at 4.28:1 (the Bowerbird style.css:16 case)' {
    $m = Get-FixtureModel
    $r = @(Find-FgContrast -Rules $m.Rules -Nodes $m.Nodes -ChangedPaths @('web/style.css'))
    $f = @($r | Where-Object { $_.Kind -eq 'low-contrast' -and $_.Path -eq 'web/style.css' -and $_.Line -eq 2 })
    $f.Count | Should -Be 1
    $f[0].Match | Should -Be '4.28:1'
    $f[0].Severity | Should -Be 'FAIL'
    $f[0].Note | Should -Match 'light'
  }
  It 'warns when a background cannot be resolved statically' {
    $m = Get-FixtureModel
    @(Find-FgContrast -Rules $m.Rules -Nodes $m.Nodes -ChangedPaths @('web/style.css') | Where-Object { $_.Kind -eq 'unresolved' -and $_.Line -eq 4 })[0].Severity | Should -Be 'WARN'
  }
  It 'reports a pre-existing problem as WARN when nothing related changed' {
    $m = Get-FixtureModel
    @(Find-FgContrast -Rules $m.Rules -Nodes $m.Nodes -ChangedPaths @('README.md') | Where-Object { $_.Kind -eq 'low-contrast' })[0].Severity | Should -Be 'WARN'
  }
  It 'fails when the token file changed' {
    $m = Get-FixtureModel
    @(Find-FgContrast -Rules $m.Rules -Nodes $m.Nodes -ChangedPaths @('web/tokens.css') | Where-Object { $_.Kind -eq 'low-contrast' })[0].Severity | Should -Be 'FAIL'
  }
}

Describe 'stylesheet page context' {
  It 'does not mix two pages sharing token names and still detects a bad page' {
    $dir = Join-Path $TestDrive 'separate-pages'
    New-TestRepo $dir
    [IO.File]::WriteAllText((Join-Path $dir 'dark.css'), ':root{--fg:#fff;--bg:#000}body{background:var(--bg);color:var(--fg)}')
    [IO.File]::WriteAllText((Join-Path $dir 'light.css'), ':root{--fg:#000;--bg:#fff}body{background:var(--bg);color:var(--fg)}')
    [IO.File]::WriteAllText((Join-Path $dir 'dark.html'), '<html><head><link rel="stylesheet" href="dark.css"></head><body>dark</body></html>')
    [IO.File]::WriteAllText((Join-Path $dir 'light.html'), '<html><head><link rel="stylesheet" href="light.css"></head><body>light</body></html>')
    Invoke-TestGit $dir @('add', '-A')
    @(Find-FgContrastInRepo -RepoPath $dir -ChangedPaths @('dark.css','light.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
    [IO.File]::WriteAllText((Join-Path $dir 'light.css'), ':root{--fg:#eee;--bg:#fff}body{background:var(--bg);color:var(--fg)}')
    $bad = @(Find-FgContrastInRepo -RepoPath $dir -ChangedPaths @('light.css') | Where-Object Severity -eq 'FAIL')
    $bad.Count | Should -Be 1
    $bad[0].Path | Should -Be 'light.css'
  }
  It 'follows local CSS imports before the importing stylesheet' {
    $dir = Join-Path $TestDrive 'imported-tokens'
    New-TestRepo $dir
    [IO.File]::WriteAllText((Join-Path $dir 'tokens.css'), ':root{--fg:#fff;--bg:#000}')
    [IO.File]::WriteAllText((Join-Path $dir 'page.css'), '@import "tokens.css";body{background:var(--bg);color:var(--fg)}')
    [IO.File]::WriteAllText((Join-Path $dir 'index.html'), '<html><head><link rel="stylesheet" href="page.css"></head><body>text</body></html>')
    Invoke-TestGit $dir @('add', '-A')
    @(Find-FgContrastInRepo -RepoPath $dir -ChangedPaths @('tokens.css','page.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 0
    [IO.File]::WriteAllText((Join-Path $dir 'tokens.css'), ':root{--fg:#222;--bg:#000}')
    @(Find-FgContrastInRepo -RepoPath $dir -ChangedPaths @('tokens.css') | Where-Object Severity -eq 'FAIL').Count | Should -Be 1
  }
}
