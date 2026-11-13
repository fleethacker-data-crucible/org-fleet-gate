# fleet-gate: org-wide PR check for fleethacker-data-crucible. MIT license.
# Windows PowerShell 5.1 compatible; every check is a separate function so it can be tested.
foreach ($f in 'Common', 'Sensitive', 'Binaries', 'Workflows', 'HouseRules', 'Contrast', 'SecurityPaths', 'Report', 'Policy') {
  . ([System.IO.Path]::Combine($PSScriptRoot, 'lib', "$f.ps1"))
}
$script:FgDataDir = [System.IO.Path]::Combine($PSScriptRoot, 'data')
function Get-FgDataPath { param([string]$Name) return [System.IO.Path]::Combine($script:FgDataDir, $Name) }
Export-ModuleMember -Function * -Variable FgLargeAssetHelp
