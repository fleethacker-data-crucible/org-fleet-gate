# Runs the fleet-gate tests with Pester 5.7.1 (the runner also has 3.4 and 6.x).
param([switch]$CI)
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 5.7.1 -Force
$cfg = New-PesterConfiguration
$cfg.Run.Path = $PSScriptRoot
$cfg.Run.Exit = [bool]$CI
$cfg.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $cfg
