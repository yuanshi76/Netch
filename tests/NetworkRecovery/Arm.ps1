param([Parameter(Mandatory=$true)][string]$Plan)
$ErrorActionPreference = 'Stop'
$planPath = (Resolve-Path -LiteralPath $Plan).Path
$session = Split-Path -Parent $planPath
$record = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if (Test-Path -LiteralPath (Join-Path $session 'test-started')) { throw 'Never re-arm an already started session.' }
if (Test-Path -LiteralPath (Join-Path $session 'ready.json')) { throw 'Use a fresh plan; a prior deadline cannot be extended.' }
if (-not $record.Rehearsal -and -not $record.RestartOriginal) { throw 'Install and verify preview.9 before arming automatic reconnect.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $record.Rehearsal -and -not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Arm requires administrator rights before testing.' }
$taskName = 'NetchAcceptanceRecovery-' + [Guid]::NewGuid().ToString('N')
$shellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script = Join-Path $PSScriptRoot 'Watchdog.ps1'
$arguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $script + '" -Plan "' + $planPath + '"'
$worker = $null
try {
    $delay = if ($record.Rehearsal) { 7 } else { 240 }
    $action = New-ScheduledTaskAction -Execute $shellExe -Argument ($arguments + ' -RecoverNow') -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($delay)
    $level = if ($record.Rehearsal) { 'Limited' } else { 'Highest' }
    $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel $level
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $null = Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    if ((Get-ScheduledTask -TaskName $taskName).State -eq 'Disabled') { throw 'Backup task disabled.' }
    @{TaskName=$taskName; BackupUtc=(Get-Date).AddSeconds($delay).ToUniversalTime().ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $session 'backup-task.json') -Encoding UTF8
    $worker = Start-Process -FilePath $shellExe -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath (Join-Path $session 'ready.json'))) {
        if ($worker.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'Recovery worker did not become ready; no test is permitted.' }
        Start-Sleep -Milliseconds 100
    }
    $ready = Get-Content -LiteralPath (Join-Path $session 'ready.json') -Raw | ConvertFrom-Json
    if ($ready.WorkerId -ne $worker.Id -or $ready.PlanSha256 -ne (Get-FileHash -LiteralPath $planPath).Hash) { throw 'Readiness identity mismatch.' }
    'Armed independent worker and backup task. No network settings have changed.'
    $ready
} catch {
    # No test-started exists: either worker will exit without touching live state.
    if ($null -ne $worker -and -not $worker.HasExited) { $worker.Kill() }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}
