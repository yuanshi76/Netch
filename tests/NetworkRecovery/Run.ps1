param([Parameter(Mandatory=$true)][string]$Plan,[switch]$RecoveryOnly)
# One bounded full-process or TUN Fake-IP window. No packet monitor or FastLink control.
$ErrorActionPreference='Stop'
$env:PSModulePath=(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules')+';'+$env:PSModulePath
$planPath=(Resolve-Path -LiteralPath $Plan).Path
$session=Split-Path -Parent $planPath
$record=Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($record.PSObject.Properties.Name -contains 'FastLinkAdapter') { throw 'Refusing retired adapter-disable plan before arming or stopping any process.' }
$log=Join-Path $session 'supervisor.log'
function Note([string]$text) { Add-Content -LiteralPath $log -Value ((Get-Date).ToUniversalTime().ToString('o')+' '+$text) }
$armed=$false
try {
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights are required before arming.' }
    if ([DateTime]::UtcNow - [DateTime]::Parse($record.PreparedUtc).ToUniversalTime() -gt [TimeSpan]::FromMinutes(10)) { throw 'Snapshot expired; prepare again.' }
    if (-not $record.RestartOriginal) { throw 'Verified automatic reconnect is required.' }
    if ((Get-FileHash -LiteralPath $record.OriginalExe).Hash -ne $record.OriginalExeSha256 -or (Get-FileHash -LiteralPath (Join-Path (Split-Path -Parent $record.OriginalExe) 'data\settings.json')).Hash -ne $record.OriginalSettingsSha256) { throw 'Original executable/settings changed since preparation.' }
    $stage=Get-Content -LiteralPath (Join-Path $session 'staged.json') -Raw | ConvertFrom-Json
    $exe=Join-Path $record.TestDirectory 'host\DnsRegression.exe'
    if ((Get-FileHash -LiteralPath $exe).Hash -ne $stage.HostSha256 -or (Get-FileHash -LiteralPath (Join-Path $record.TestDirectory 'host\Netch.dll')).Hash -ne $stage.DllSha256) { throw 'Staged host changed.' }
    & $exe $session ('--guarded-preflight='+$planPath) *> (Join-Path $session 'preflight.log')
    if($LASTEXITCODE -ne 0) { throw 'Staged executable preflight failed; original Netch will not be stopped.' }
    foreach ($entry in $record.OriginalProcesses) {
        $process=Get-Process -Id $entry.Id -ErrorAction Stop
        if ($process.Path -ne $entry.Path -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $entry.StartTicks) { throw 'Original process identity changed.' }
    }
    # All preparation is complete before the fixed local deadline starts.
    $null=& (Join-Path $PSScriptRoot 'Arm.ps1') -Plan $planPath
    $armed=$true
    Note 'Both local recovery worker and scheduled backup are ready.'
    $null=New-Item -ItemType File -Path (Join-Path $session 'test-started')
    foreach ($entry in $record.OriginalProcesses) {
        $process=Get-Process -Id $entry.Id -ErrorAction SilentlyContinue
        if ($null -eq $process) { continue }
        if ($process.Path -ne $entry.Path -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $entry.StartTicks) { throw 'Original process identity changed during stop.' }
        Stop-Process -Id $process.Id -Force
        if (-not $process.WaitForExit(5000)) { throw 'Original process did not exit.' }
    }
    Note 'Recorded original Netch processes exited; no other application process was stopped.'
    if($RecoveryOnly) { Note 'Recovery-only window: no test mode or Fake-IP was started.'; return }
    $arguments='"'+(Split-Path -Parent $PSScriptRoot)+'" --guarded-plan="'+$planPath+'"'
    $hostProcess=Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory (Split-Path -Parent $exe) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $session 'acceptance.log') -RedirectStandardError (Join-Path $session 'acceptance-error.log')
    $hostProcess.Refresh()
    $owned=@(@{Id=$hostProcess.Id; Path=$hostProcess.Path; StartTicks=$hostProcess.StartTime.ToUniversalTime().Ticks.ToString()})
    ConvertTo-Json -InputObject $owned | Set-Content -LiteralPath (Join-Path $session 'owned-processes.json.tmp') -Encoding UTF8
    Move-Item -LiteralPath (Join-Path $session 'owned-processes.json.tmp') -Destination (Join-Path $session 'owned-processes.json') -Force
    $null=New-Item -ItemType File -Path (Join-Path $session 'run-host')
    Note ('Test host registered before permission to mutate network. PID '+$hostProcess.Id)
    if (-not $hostProcess.WaitForExit(120000)) { Note 'Host exceeded its working budget; requesting recovery.' }
    else { Note ('Host completed with exit code '+$hostProcess.ExitCode) }
} catch { Note ('Test failed: '+$_.Exception.Message) }
finally {
    if ($armed) {
        $null=New-Item -ItemType File -Path (Join-Path $session 'restore-now') -Force
        Note 'Requested the same independent restoration path.'
        $deadline=[DateTime]::UtcNow.AddSeconds(160)
        while (-not (Test-Path -LiteralPath (Join-Path $session 'restored.json')) -and -not (Test-Path -LiteralPath (Join-Path $session 'failed.json'))) {
            if ([DateTime]::UtcNow -ge $deadline) { break }; Start-Sleep -Milliseconds 300
        }
        if (Test-Path -LiteralPath (Join-Path $session 'restored.json')) {
            $backup=Get-Content -LiteralPath (Join-Path $session 'backup-task.json') -Raw | ConvertFrom-Json
            if (-not $backup.TaskName.StartsWith('NetchAcceptanceRecovery-')) { throw 'Unexpected task identity.' }
            Unregister-ScheduledTask -TaskName $backup.TaskName -Confirm:$false
            Note 'Recovery completed; backup task removed.'
        } else { Note 'No verified recovery completion; backup task remains armed.' }
    }
}
