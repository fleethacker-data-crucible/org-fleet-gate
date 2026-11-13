# Shared setup for the fleet-gate Pester tests (Pester 5.7.1, Windows PowerShell 5.1 compatible).
$script:FgRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..'))
Import-Module ([System.IO.Path]::Combine($script:FgRoot, 'FleetGate.psm1')) -Force
$script:Fx = [System.IO.Path]::Combine($PSScriptRoot, 'fixtures')
function New-TestAdded { param([string]$Path, [string]$Text, [int]$Line = 1) [pscustomobject]@{ Path = $Path; Line = $Line; Text = $Text } }
function Get-TestRows { param([string]$Name) return @(Read-FgTsv (Get-FgDataPath $Name) 2) }
function New-TestRepo {
  # A throwaway git repo with an MIT LICENSE committed.
  param([string]$Dir)
  $null = New-Item -ItemType Directory -Path $Dir -Force
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & git -C $Dir init -q 2>$null
  & git -C $Dir config user.email 'test@users.noreply.github.com'
  & git -C $Dir config user.name 'fleet-gate test'
  & git -C $Dir config commit.gpgsign false
  [System.IO.File]::WriteAllText([System.IO.Path]::Combine($Dir, 'LICENSE'), "MIT License`n`nPermission is hereby granted, free of charge, to any person obtaining a copy`n")
  & git -C $Dir add -A 2>$null
  & git -C $Dir commit -q -m init 2>$null
  $ErrorActionPreference = $old
}
function Invoke-TestGit { param([string]$Dir, [string[]]$GitArgs) $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & git -C $Dir @GitArgs 2>$null } finally { $ErrorActionPreference = $old } }
