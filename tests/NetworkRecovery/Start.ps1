param([switch]$RecoveryOnly,[ValidateSet('FullProcess','Tun')][string]$AcceptanceMode='FullProcess',[switch]$TemporarilyDisableFastLink)
# Elevated entry point. Preflight and copying happen before the timer is armed.
$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$directory=Join-Path $workspace '.build\network-acceptance'
$null=New-Item -ItemType Directory -Path $directory -Force
$entryLog=Join-Path $directory 'entry.log'
try {
    $env:PSModulePath=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')+';'+$env:PSModulePath
    $prepared=@(& (Join-Path $PSScriptRoot 'Prepare.ps1') -AcceptanceMode $AcceptanceMode -TemporarilyDisableFastLink:$TemporarilyDisableFastLink)
    $plan=($prepared | Where-Object { $_ -isnot [string] }).PlanPath
    if (-not $plan) { throw 'No recovery plan was prepared.' }
    $plan | Set-Content -LiteralPath (Join-Path $directory 'pending-plan.txt') -Encoding UTF8
    & (Join-Path $PSScriptRoot 'Stage.ps1') -Plan $plan | Add-Content -LiteralPath $entryLog
    & (Join-Path $PSScriptRoot 'Run.ps1') -Plan $plan -RecoveryOnly:$RecoveryOnly
} catch { Add-Content -LiteralPath $entryLog -Value ((Get-Date).ToString('o')+' '+$_.Exception.Message); exit 1 }
