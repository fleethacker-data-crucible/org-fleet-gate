BeforeAll {
  . ([System.IO.Path]::Combine($PSScriptRoot, '_Helpers.ps1'))
  function Get-Wf { param([string]$Name) $p = [System.IO.Path]::Combine($script:Fx, 'workflows', $Name); return @(Find-FgWorkflowShells -Path ".github/workflows/$Name" -Lines ([System.IO.File]::ReadAllLines($p))) }
}

Describe 'Find-FgWorkflowShells' {
  It 'fails shell: python (the prune-merged-branches case)' {
    $r = Get-Wf 'python-shell.yml'
    $r[0].Kind | Should -Be 'non-powershell-shell'
    $r[0].Severity | Should -Be 'FAIL'
    $r[0].Line | Should -Be 11   # the step's run: line
  }
  It 'passes shell: powershell from defaults and per step' {
    @(Get-Wf 'good.yml' | Where-Object { $_.Severity -ne 'PASS' }).Count | Should -Be 0
  }
  It 'fails a missing shell on Windows and warns on shell: powershell on Linux' {
    $r = Get-Wf 'missing-shell.yml'
    @($r | Where-Object { $_.Kind -eq 'missing-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    @($r | Where-Object { $_.Kind -eq 'linux-powershell' -and $_.Severity -eq 'WARN' }).Count | Should -Be 1
    @($r | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'lets Linux jobs use bash, sh or python' {
    $r = Get-Wf 'linux-shells.yml'
    @($r | Where-Object { $_.Note -match "job '(unit|docker)'" }).Count | Should -Be 0
  }
  It 'keeps the Windows rule when runs-on is an expression' {
    $r = Get-Wf 'linux-shells.yml'
    $m = @($r | Where-Object { $_.Note -match "job 'matrix'" })
    @($m | Where-Object { $_.Kind -eq 'non-powershell-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    @($m | Where-Object { $_.Kind -eq 'missing-shell' -and $_.Severity -eq 'WARN' }).Count | Should -Be 1
    $m[0].Note | Should -Match "can't tell is Linux"
  }
  It 'fails a macOS runner' {
    @(Get-Wf 'linux-shells.yml' | Where-Object { $_.Kind -eq 'unsupported-runner' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'says the rule is for Windows runners and Linux may use python' {
    (Get-Wf 'python-shell.yml')[0].Note | Should -Match 'Windows runners must use shell: powershell.*Linux runners may use bash, sh or python'
  }
  It 'classifies runs-on' {
    Get-FgRunnerOs '[self-hosted, Windows, X64]' | Should -Be 'windows'
    Get-FgRunnerOs 'ubuntu-latest' | Should -Be 'linux'
    Get-FgRunnerOs ' self-hosted linux x64 docker' | Should -Be 'linux'
    Get-FgRunnerOs '[self-hosted, linux, windows]' | Should -Be 'windows'
    Get-FgRunnerOs '${{ matrix.os }}' | Should -Be 'unknown'
    Get-FgRunnerOs 'self-hosted' | Should -Be 'unknown'
  }
}

Describe 'Get-FgRunnerOs with expressions' {
  It 'treats the vars-with-literal-fallback pattern as Linux' {
    Get-FgRunnerOs "`${{ vars.CROWS_NEST_RUNS_ON && fromJSON(vars.CROWS_NEST_RUNS_ON) || 'ubuntu-latest' }}" | Should -Be 'linux'
    Get-FgRunnerOs "`${{ vars.R && fromJSON(vars.R) || 'ubuntu-26.04' }}" | Should -Be 'linux'
    Get-FgRunnerOs "`${{ vars.R && fromJSON(vars.R) || fromJSON('[`"self-hosted`",`"linux`",`"docker`"]') }}" | Should -Be 'linux'
  }
  It 'keeps the Windows rule for the same pattern with a Windows fallback' {
    Get-FgRunnerOs "`${{ vars.R && fromJSON(vars.R) || 'windows-latest' }}" | Should -Be 'unknown'
  }
  It 'keeps the Windows rule for an expression with no literals' {
    Get-FgRunnerOs '${{ matrix.os }}' | Should -Be 'unknown'
    Get-FgRunnerOs '${{ fromJSON(vars.R) }}' | Should -Be 'unknown'
  }
  It 'treats an all-Linux literal array or object as Linux' {
    Get-FgRunnerOs '[self-hosted, Linux, X64]' | Should -Be 'linux'
    Get-FgRunnerOs "`${{ fromJSON('[`"self-hosted`", `"Linux`", `"X64`"]') }}" | Should -Be 'linux'
    Get-FgRunnerOs "`${{ fromJSON('{`"group`": `"zombie`", `"labels`": [`"linux`", `"docker`"]}') }}" | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ fromJSON('{`"labels`": [`"linux`", `"docker`"]}') }}" | Should -Be 'linux'
    Get-FgRunnerOs ' group: zombie labels: [linux, docker]' | Should -Be 'linux'
  }
  It 'keeps the Windows rule when Linux and Windows labels are mixed' {
    Get-FgRunnerOs "`${{ github.event_name == 'push' && 'ubuntu-latest' || 'windows-latest' }}" | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ vars.R && 'windows-2022' || 'ubuntu-latest' }}" | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ fromJSON('[`"self-hosted`", `"linux`", `"windows`"]') }}" | Should -Be 'unknown'
    Get-FgRunnerOs '[self-hosted, Linux, Windows]' | Should -Be 'windows'
  }
  It 'keeps the Windows rule when a literal is neither Linux nor neutral and there is no Linux fallback' {
    Get-FgRunnerOs "`${{ vars.R || 'self-hosted' }}" | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ github.event_name == 'push' && 'ubuntu-latest' }}" | Should -Be 'unknown'
  }
  It 'never calls a macOS literal Linux' {
    Get-FgRunnerOs "`${{ vars.R && 'macos-latest' || 'ubuntu-latest' }}" | Should -Be 'unknown'
  }
  It 'keeps the Windows rule for matrix.* or inputs.* with no Linux literal fallback' {
    Get-FgRunnerOs '${{ matrix.runner }}' | Should -Be 'unknown'
    Get-FgRunnerOs '${{ inputs.runner }}' | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ inputs.runner || 'windows-latest' }}" | Should -Be 'unknown'
    Get-FgRunnerOs "`${{ inputs.runner || 'self-hosted' }}" | Should -Be 'unknown'
  }
  It 'treats inputs.* with a Linux literal fallback as Linux' {
    Get-FgRunnerOs "`${{ inputs.runner || 'ubuntu-latest' }}" | Should -Be 'linux'
  }
}

Describe 'Find-FgWorkflowShells with expression runs-on' {
  BeforeAll { $script:Ex = Get-Wf 'runs-on-expressions.yml' }
  It 'lets the crows-nest pattern use shell: bash' {
    @($script:Ex | Where-Object { $_.Note -match "job 'vars-linux'" }).Count | Should -Be 0
  }
  It 'fails bash with a Windows fallback' {
    @($script:Ex | Where-Object { $_.Note -match "job 'vars-windows'" -and $_.Kind -eq 'non-powershell-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'fails bash with no literals and says how to mark a Linux job' {
    $m = @($script:Ex | Where-Object { $_.Note -match "job 'no-literals'" })
    @($m | Where-Object { $_.Kind -eq 'non-powershell-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
    $m[0].Note | Should -Match "literal Linux fallback"
  }
  It 'lets an all-Linux fromJSON literal use sh' {
    @($script:Ex | Where-Object { $_.Note -match "job 'json-linux'" }).Count | Should -Be 0
  }
  It 'fails bash with mixed Linux and Windows literals' {
    @($script:Ex | Where-Object { $_.Note -match "job 'mixed'" -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'fails bash on matrix.runner with a windows-latest matrix entry' {
    @($script:Ex | Where-Object { $_.Note -match "job 'matrix-runner'" -and $_.Kind -eq 'non-powershell-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'fails bash on inputs.runner with no fallback' {
    @($script:Ex | Where-Object { $_.Note -match "job 'inputs-runner'" -and $_.Kind -eq 'non-powershell-shell' -and $_.Severity -eq 'FAIL' }).Count | Should -Be 1
  }
  It 'lets inputs.runner with a Linux literal fallback use bash' {
    @($script:Ex | Where-Object { $_.Note -match "job 'inputs-fallback'" }).Count | Should -Be 0
  }
  It 'ignores a trailing comment on runs-on' {
    @($script:Ex | Where-Object { $_.Note -match "job 'commented'" }).Count | Should -Be 0
  }
  It 'has exactly the expected FAILs' {
    @($script:Ex | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 5
  }
}

Describe 'Find-FgWorkflowDanger' {
  It 'fails a pwn-request checkout and script injection, warns on unpinned actions' {
    $p = [System.IO.Path]::Combine($script:Fx, 'workflows', 'target.yml')
    $r = @(Find-FgWorkflowDanger -Path '.github/workflows/target.yml' -Lines ([System.IO.File]::ReadAllLines($p)))
    @($r | Where-Object { $_.Kind -eq 'untrusted-checkout' -and $_.Severity -eq 'FAIL' }).Count | Should -BeGreaterThan 0
    @($r | Where-Object { $_.Kind -eq 'script-injection' -and $_.Severity -eq 'FAIL' }).Count | Should -BeGreaterThan 0
    @($r | Where-Object { $_.Kind -eq 'unpinned-action' }).Count | Should -BeGreaterThan 0
  }
  It 'is quiet on the good workflow' {
    $p = [System.IO.Path]::Combine($script:Fx, 'workflows', 'good.yml')
    @(Find-FgWorkflowDanger -Path '.github/workflows/good.yml' -Lines ([System.IO.File]::ReadAllLines($p)) | Where-Object { $_.Severity -eq 'FAIL' }).Count | Should -Be 0
  }
}
