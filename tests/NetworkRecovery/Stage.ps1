param([Parameter(Mandatory=$true)][string]$Plan)
# Copies only; does not stop an app, arm a timer, or mutate system network state.
$ErrorActionPreference='Stop'
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$planPath=(Resolve-Path -LiteralPath $Plan).Path
$record=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
$session=Split-Path -Parent $planPath
$testDirectory=[IO.Path]::GetFullPath($record.TestDirectory)
if ($testDirectory -ne (Join-Path $session 'test') -or -not $testDirectory.StartsWith((Join-Path $workspace '.build\network-acceptance\session-'),[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected staging directory.' }
if (Test-Path -LiteralPath (Join-Path $session 'ready.json')) { throw 'Do not stage an armed session.' }
$source=Join-Path $workspace 'tests\DnsRegression\bin\x64\Release\net8.0-windows10.0.17763.0\win-x64'
foreach ($name in @('host','probe')) {
    $destination=Join-Path $testDirectory $name
    $null=New-Item -ItemType Directory -Path $destination -Force
    Get-ChildItem -LiteralPath $source | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse -Force }
}
$original=Split-Path -Parent $record.OriginalExe
foreach ($name in @('bin','i18n')) { Copy-Item -LiteralPath (Join-Path $original $name) -Destination (Join-Path $testDirectory 'host') -Recurse -Force }
$data=Join-Path $testDirectory 'host\data'
$null=New-Item -ItemType Directory -Path $data -Force
if (Test-Path -LiteralPath (Join-Path $session 'original-dns-protection.json')) {
    Copy-Item -LiteralPath (Join-Path $session 'original-dns-protection.json') -Destination (Join-Path $data 'dns-protection.json')
}
# The original and staged host share only the saved recovery baseline, no live files.
@{ HostSha256=(Get-FileHash -LiteralPath (Join-Path $testDirectory 'host\DnsRegression.exe')).Hash; DllSha256=(Get-FileHash -LiteralPath (Join-Path $testDirectory 'host\Netch.dll')).Hash } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $session 'staged.json') -Encoding UTF8
'Staged isolated host and external probe; no network state changed.'
