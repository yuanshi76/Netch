param([switch]$ExerciseBackupTask)
$ErrorActionPreference = 'Stop'
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$session = Join-Path $workspace ('.build\network-acceptance\rehearsal-' + [Guid]::NewGuid().ToString('N'))
$testDirectory = Join-Path $session 'test'
$null = New-Item -ItemType Directory -Path $testDirectory -Force
$shellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$fixture = Join-Path $testDirectory 'fixture.ps1'
'Start-Sleep -Seconds 300' | Set-Content -LiteralPath $fixture -Encoding UTF8
$child = Start-Process -FilePath $shellExe -ArgumentList @('-NoProfile','-File',('"' + $fixture + '"')) -WindowStyle Hidden -PassThru
$child.Refresh()
$baseline = '{"dns":"original","routes":["original"],"firewall":["original"],"FastLink":"unchanged"}'
$baseline | Set-Content -LiteralPath (Join-Path $session 'fixture-baseline.json') -Encoding UTF8
'{"dns":"test","routes":["test"],"firewall":["test"],"FastLink":"unchanged"}' | Set-Content -LiteralPath (Join-Path $session 'fixture-current.json') -Encoding UTF8
@(@{Id=$child.Id; Path=$child.Path; StartTicks=$child.StartTime.ToUniversalTime().Ticks.ToString()}) | ConvertTo-Json -AsArray | Set-Content -LiteralPath (Join-Path $session 'owned-processes.json') -Encoding UTF8
$plan = @{ Version=1; Rehearsal=$true; TimeoutSeconds=3; TestDirectory=$testDirectory; OriginalExe=(Join-Path $testDirectory 'Netch.exe'); FixtureProcessId=$child.Id; RestartOriginal=$false }
$planPath = Join-Path $session 'plan.json'
$plan | ConvertTo-Json | Set-Content -LiteralPath $planPath -Encoding UTF8
$worker = $null
try {
    if ($ExerciseBackupTask) {
        $null = & (Join-Path $PSScriptRoot 'Arm.ps1') -Plan $planPath
        $ready = Get-Content -LiteralPath (Join-Path $session 'ready.json') -Raw | ConvertFrom-Json
        $worker = Get-Process -Id $ready.WorkerId
        $null = New-Item -ItemType File -Path (Join-Path $session 'test-started')
        $worker.Kill(); $worker.WaitForExit()
    } else {
        $null = New-Item -ItemType File -Path (Join-Path $session 'test-started')
        $worker = Start-Process -FilePath $shellExe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"' + (Join-Path $PSScriptRoot 'Watchdog.ps1') + '"'),'-Plan',('"' + $planPath + '"')) -WindowStyle Hidden -PassThru
        if (-not $worker.WaitForExit(15000)) { throw 'Watchdog rehearsal timed out.' }
        if ($worker.ExitCode -ne 0) { throw ('Watchdog exited with error; inspect ' + $session) }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while (-not (Test-Path -LiteralPath (Join-Path $session 'restored.json'))) { if ([DateTime]::UtcNow -ge $deadline) { throw 'Backup recovery did not complete.' }; Start-Sleep -Milliseconds 200 }
    $child.Refresh(); if (-not $child.HasExited) { throw 'Fixture test process survived deadline.' }
    if ((Get-FileHash -LiteralPath (Join-Path $session 'fixture-current.json')).Hash -ne (Get-FileHash -LiteralPath (Join-Path $session 'fixture-baseline.json')).Hash) { throw 'Fixture state was not restored exactly.' }
    if (-not (Test-Path -LiteralPath (Join-Path $session 'restored.json'))) { throw 'No durable recovery completion.' }
    'PASS independent timer terminated only its recorded fixture and restored baseline without network changes.'
    'Evidence: ' + $session
} finally {
    if (-not $child.HasExited) { $child.Kill() }
    $child.Dispose(); if ($null -ne $worker) { $worker.Dispose() }
    if ($ExerciseBackupTask -and (Test-Path -LiteralPath (Join-Path $session 'backup-task.json'))) {
        $task = Get-Content -LiteralPath (Join-Path $session 'backup-task.json') -Raw | ConvertFrom-Json
        if (-not $task.TaskName.StartsWith('NetchAcceptanceRecovery-')) { throw 'Unexpected backup task identity.' }
        Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
    }
}
