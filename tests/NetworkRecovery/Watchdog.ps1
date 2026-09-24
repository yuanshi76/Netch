param(
    [Parameter(Mandatory=$true)][string]$Plan,
    [switch]$RecoverNow
)
# This independent Windows process never needs Internet, Codex, or a parent heartbeat.
# It is not included in the product and creates no debug buttons.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$env:PSModulePath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules') + ';' + $env:PSModulePath
function File-Hash([string]$path) {
    $file = [IO.File]::OpenRead($path); $hash = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hash.ComputeHash($file)).Replace('-','') } finally { $file.Dispose(); $hash.Dispose() }
}
$planPath = [IO.Path]::GetFullPath($Plan)
$stateDirectory = Split-Path -Parent $planPath
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $workspace '.build\network-acceptance')) + '\'
if (-not ($stateDirectory + '\').StartsWith($allowedRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Recovery plan must be in the isolated acceptance directory.' }
$record = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
if ($record.Version -ne 1 -or $record.TimeoutSeconds -lt 1 -or $record.TimeoutSeconds -gt 180) { throw 'Invalid recovery plan version or deadline.' }
if (-not $record.Rehearsal -and $record.TimeoutSeconds -ne 180) { throw 'Live tests require the fixed three-minute deadline.' }
$testDirectory = [IO.Path]::GetFullPath($record.TestDirectory)
if (-not ($testDirectory + '\').StartsWith($stateDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Test directory escapes its recovery session.' }
foreach ($item in Get-Item -LiteralPath $stateDirectory,$testDirectory) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse points are not allowed for recovery.' }
}
$originalExe = [IO.Path]::GetFullPath($record.OriginalExe)
if (-not $record.Rehearsal) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Recovery must already have administrator rights before a test begins.' }
    if ([IO.Path]::GetFileName($originalExe) -ne 'Netch.exe' -or (File-Hash $originalExe) -ne $record.OriginalExeSha256) { throw 'Original EXE changed; do not start testing.' }
    # These local modules must load before readiness, not after connectivity is lost.
    Import-Module NetTCPIP -ErrorAction Stop
    Import-Module NetAdapter -ErrorAction Stop
    Import-Module NetSecurity -ErrorAction Stop
    $null = New-Object -ComObject HNetCfg.FwPolicy2
}
$logPath = Join-Path $stateDirectory 'recovery.log'
function Write-RecoveryLog([string]$message) { Add-Content -LiteralPath $logPath -Value ((Get-Date).ToUniversalTime().ToString('o') + ' ' + $message) }
function Save-Json([string]$name, $value) {
    $target = Join-Path $stateDirectory $name
    $value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath ($target + '.tmp') -Encoding UTF8
    Move-Item -LiteralPath ($target + '.tmp') -Destination $target -Force
}
function Stop-RecordedProcess($entry) {
    $process = Get-Process -Id $entry.Id -ErrorAction SilentlyContinue
    if ($null -eq $process) { return }
    # PID reuse cannot authorize killing a different process. Never kill by name.
    if ($process.StartTime.ToUniversalTime().Ticks.ToString() -ne [string]$entry.StartTicks -or $process.Path -ne $entry.Path) { Write-RecoveryLog 'Skipped a changed process identity.'; return }
    if (-not $process.Path.StartsWith($testDirectory + '\', [StringComparison]::OrdinalIgnoreCase) -and -not ($record.Rehearsal -and $entry.Id -eq $record.FixtureProcessId)) { throw 'Process is outside the isolated test directory.' }
    if (-not $record.Rehearsal) {
        foreach ($child in @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $process.Id))) {
            if ($child.ExecutablePath -and $child.ExecutablePath.StartsWith($testDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) {
                $ownedChild=Get-Process -Id $child.ProcessId -ErrorAction SilentlyContinue
                if ($null -ne $ownedChild) { Stop-RecordedProcess @{Id=$ownedChild.Id; Path=$ownedChild.Path; StartTicks=$ownedChild.StartTime.ToUniversalTime().Ticks.ToString()} }
            }
        }
    }
    Stop-Process -Id $process.Id -Force
    if (-not $process.WaitForExit(5000)) { throw 'Owned test process did not exit.' }
    Write-RecoveryLog ('Stopped owned test PID ' + $entry.Id)
}
function Test-Reconnected([int]$processId) {
    # A reply must come from the newly restarted Netch listener, not another app.
    if (@(Get-NetUDPEndpoint -LocalAddress '127.0.0.1' -LocalPort 53 -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $processId }).Count -eq 0) { return $false }
    $client=New-Object Net.Sockets.UdpClient
    try {
        $client.Client.ReceiveTimeout=1000
        $client.Connect('127.0.0.1',53)
        [byte[]]$query=@(91,47,1,0,0,1,0,0,0,0,0,0,7,101,120,97,109,112,108,101,3,99,111,109,0,0,1,0,1)
        $null=$client.Send($query,$query.Length)
        $peer=New-Object Net.IPEndPoint([Net.IPAddress]::Loopback,0)
        $answer=$client.Receive([ref]$peer)
        return $answer.Length -ge 29 -and $answer[0] -eq 91 -and $answer[1] -eq 47 -and ($answer[2] -band 128) -ne 0 -and ($answer[3] -band 15) -eq 0 -and ($answer[6]*256+$answer[7]) -gt 0
    } catch { return $false } finally { $client.Dispose() }
}
function Run-Netsh([string[]]$arguments) {
    # All arguments below are fixed verbs or validated numerical/IP values.
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $env:SystemRoot 'System32\netsh.exe'
    $info.Arguments = $arguments -join ' '
    $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($info)
    try {
        if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'DNS restore command timed out.' }
        if ($process.ExitCode -ne 0) { throw ('DNS restore command failed: ' + $process.ExitCode) }
    } finally { $process.Dispose() }
}
function Restore-PausedAdapter {
    if(-not ($record.PSObject.Properties.Name -contains 'FastLinkAdapter') -or -not (Test-Path -LiteralPath (Join-Path $stateDirectory 'fastlink-pause-requested'))) { return }
    $adapter=@(Get-NetAdapter -IncludeHidden | Where-Object { [Guid]$_.InterfaceGuid -eq [Guid]$record.FastLinkAdapter.Id -and $_.Name -eq $record.FastLinkAdapter.Name })
    if($adapter.Count -ne 1) { throw 'The recorded FastLink adapter is missing; refusing to operate on another adapter.' }
    if($adapter[0].Status -eq 'Disabled') { $adapter[0] | Enable-NetAdapter -Confirm:$false }
    $until=[DateTime]::UtcNow.AddSeconds(15)
    do {
        $current=Get-NetAdapter -IncludeHidden | Where-Object { [Guid]$_.InterfaceGuid -eq [Guid]$record.FastLinkAdapter.Id }
        if($current.Status -eq 'Up') { Write-RecoveryLog 'Temporarily paused FastLink adapter re-enabled and Up.'; return }
        Start-Sleep -Milliseconds 250
    } while([DateTime]::UtcNow -lt $until)
    throw 'FastLink adapter did not return to Up.'
}
function Try-RestorePausedAdapter {
    try { Restore-PausedAdapter; return $true }
    catch {
        # Older test plans may refer to an adapter removed by Wintun. Failure of
        # this optional restoration must not skip the remaining DNS/route cleanup.
        Write-RecoveryLog ('External adapter restoration pending: ' + $_.Exception.Message)
        Save-Json 'adapter-restore-pending.json' @{ Error=$_.Exception.Message; Adapter=$record.FastLinkAdapter; Utc=[DateTime]::UtcNow.ToString('o') }
        return $false
    }
}
function Restore-Network {
    if ($record.Rehearsal) {
        # Only fixture files are changed in rehearsal; production recovery is separate.
        Copy-Item -LiteralPath (Join-Path $stateDirectory 'fixture-baseline.json') -Destination (Join-Path $stateDirectory 'fixture-current.json') -Force
        Write-RecoveryLog 'Rehearsal baseline restored; no system network settings changed.'
        return
    }
    $issues = New-Object 'System.Collections.Generic.List[string]'
    # Route entries are an explicit write-ahead allowlist. Existing baseline routes
    # must never be in it; a test must not add any route until its entry is durable.
    $routeFile = Join-Path $stateDirectory 'owned-routes.json'
    $routeEntries=Get-Content -LiteralPath $routeFile -Raw | ConvertFrom-Json
    $tunJournal=Join-Path $testDirectory 'host\data\tun-owned-routes.json'
    if(Test-Path -LiteralPath $tunJournal) {
        $tunEntries=Get-Content -LiteralPath $tunJournal -Raw | ConvertFrom-Json
        $routeEntries=@($routeEntries)+@($tunEntries)
    }
    foreach ($route in $routeEntries) {
        if ($null -eq $route -or ($route -is [Array] -and $route.Count -eq 0)) { continue }
        try {
            $adapter = Get-NetAdapter -IncludeHidden | Where-Object { [Guid]$_.InterfaceGuid -eq [Guid]$route.InterfaceId }
            if ($null -eq $adapter) { continue }
            $matches = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $route.NextHop -and $_.RouteMetric -eq $route.Metric })
            foreach ($match in $matches) { $match | Remove-NetRoute -Confirm:$false -ErrorAction Stop }
            $remaining = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -DestinationPrefix $route.DestinationPrefix -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -eq $route.NextHop -and $_.RouteMetric -eq $route.Metric })
            if ($remaining.Count -gt 0) { throw 'Owned route remains after deletion.' }
        } catch { $issues.Add('Route restoration: ' + $_.Exception.Message) }
    }
    foreach ($dns in $record.Dns) {
        try {
            $adapter = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object { $_.Id -eq $dns.Id }
            if ($null -eq $adapter) {
                if ($record.PSObject.Properties.Name -contains 'FastLinkAdapter' -and
                    [Guid]$dns.Id -eq [Guid]$record.FastLinkAdapter.Id -and
                    (Test-Path -LiteralPath (Join-Path $stateDirectory 'fastlink-pause-requested'))) {
                    Write-RecoveryLog 'Recorded external adapter is absent; its saved DNS remains pending while other interfaces are restored.'
                    continue
                }
                throw 'Saved adapter is unavailable.'
            }
            $properties = $adapter.GetIPProperties()
            $index = if ($dns.V6) { $properties.GetIPv6Properties().Index } else { $properties.GetIPv4Properties().Index }
            $family = if ($dns.V6) { 'ipv6' } else { 'ipv4' }
            $addresses = @($dns.StaticServers)
            foreach ($address in $addresses) { $parsed = $null; if (-not [Net.IPAddress]::TryParse($address, [ref]$parsed)) { throw 'Invalid saved DNS address.' } }
            if ($addresses.Count -eq 0) { Run-Netsh @('interface',$family,'set','dnsservers',"name=$index",'source=dhcp') }
            else {
                Run-Netsh @('interface',$family,'set','dnsservers',"name=$index",'source=static',('address=' + $addresses[0]),'validate=no')
                for ($i = 1; $i -lt $addresses.Count; $i++) { Run-Netsh @('interface',$family,'add','dnsservers',"name=$index",('address=' + $addresses[$i]),('index=' + ($i + 1)),'validate=no') }
            }
            $service = if ($dns.V6) { 'Tcpip6' } else { 'Tcpip' }
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$service\Parameters\Interfaces\$($adapter.Id)")
            try { $raw = if ($null -eq $key) { '' } else { [string]$key.GetValue('NameServer','') } } finally { if ($null -ne $key) { $key.Dispose() } }
            $actual = @($raw -split '[, ;]+' | Where-Object { $_ })
            if (($actual -join ',') -ne ($addresses -join ',')) { throw 'DNS readback does not match the saved static/DHCP setting.' }
        } catch { $issues.Add('DNS restoration: ' + $_.Exception.Message) }
    }
    try {
        $policy = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($rule in @($policy.Rules)) {
            if ($rule.Name -in @('Netch.StrictDNS.v1.TCP','Netch.StrictDNS.v1.UDP','Netch.StrictDNS.v1.IPv6','Netch.StrictDNS.v1.FakeIP') -and $rule.Grouping -eq 'Netch DNS Protection') { $policy.Rules.Remove($rule.Name) }
        }
        foreach ($rule in @($policy.Rules)) {
            if ($rule.Name -in @('Netch.StrictDNS.v1.TCP','Netch.StrictDNS.v1.UDP','Netch.StrictDNS.v1.IPv6','Netch.StrictDNS.v1.FakeIP') -and $rule.Grouping -eq 'Netch DNS Protection') { throw 'An owned DNS protection rule remains.' }
        }
        foreach ($rule in @(Get-NetFirewallRule -DisplayName 'Netch' -ErrorAction SilentlyContinue)) {
            $app = $rule | Get-NetFirewallApplicationFilter
            if ($app.Program -and $app.Program.StartsWith($testDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { $rule | Remove-NetFirewallRule }
        }
        Clear-DnsClientCache
    } catch { $issues.Add('Firewall restoration: ' + $_.Exception.Message) }
    if ($issues.Count -gt 0) { throw ($issues -join '; ') }
    Write-RecoveryLog 'Saved DNS and explicitly owned routes/rules restored and read back.'
}
# One worker performs recovery even when the secondary scheduled task also fires.
$lockPath = Join-Path $stateDirectory 'worker.lock'
try { $owner = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None') } catch { exit 2 }
try {
    if (Test-Path -LiteralPath (Join-Path $stateDirectory 'restored.json')) { exit 0 }
    $watch = [Diagnostics.Stopwatch]::StartNew()
    Save-Json 'ready.json' @{ WorkerId=$PID; DeadlineUtc=[DateTime]::UtcNow.AddSeconds($record.TimeoutSeconds).ToString('o'); PlanSha256=(File-Hash $planPath) }
    Write-RecoveryLog 'Independent recovery worker ready.'
    while (-not $RecoverNow -and $watch.Elapsed.TotalSeconds -lt $record.TimeoutSeconds) {
        if (Test-Path -LiteralPath (Join-Path $stateDirectory 'restore-now')) { break }
        Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path -LiteralPath (Join-Path $stateDirectory 'test-started'))) {
        Write-RecoveryLog 'Test never began; live state was not touched.'
        Save-Json 'restored.json' @{ Result='not-started'; Utc=[DateTime]::UtcNow.ToString('o') }; exit 0
    }
    Write-RecoveryLog 'Deadline/manual recovery triggered locally.'
    $processFile = Join-Path $stateDirectory 'owned-processes.json'
    $processEntries=Get-Content -LiteralPath $processFile -Raw | ConvertFrom-Json
    foreach ($entry in $processEntries) { if ($null -ne $entry) { Stop-RecordedProcess $entry } }
    # Restore our explicitly paused adapter even if the user already restarted Netch.
    $externalAdapterRestored = Try-RestorePausedAdapter
    # User action wins over an earlier recovery plan. Never rewrite adapter DNS
    # underneath a replacement Netch instance that the user started meanwhile.
    if (-not $record.Rehearsal) {
        $replacement=@(Get-Process Netch -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $originalExe })
        if ($replacement.Count -gt 0) {
            $healthy=$replacement.Count -eq 1 -and (Test-Reconnected $replacement[0].Id)
            Save-Json 'restored.json' @{Result='user-restarted-network-untouched'; ProxyReconnected=$healthy; NetworkRestored=$false; ExternalAdapterRestored=$externalAdapterRestored; Utc=[DateTime]::UtcNow.ToString('o')}
            Write-RecoveryLog 'User restarted original Netch; left its DNS and firewall untouched. Manual state verification required.'
            exit 0
        }
    }
    $restored = $false
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { Restore-Network; $restored = $true; break }
        catch { Write-RecoveryLog ('Restore attempt ' + $attempt + ': ' + $_.Exception.Message); Start-Sleep -Seconds 1 }
    }
    if (-not $restored) { Save-Json 'failed.json' @{ Result='restore-failed'; Utc=[DateTime]::UtcNow.ToString('o') }; exit 1 }
    # Launching the original app is optional. The original configuration is never
    # edited to force autostart. It must already support -start (preview.9+).
    if (-not $record.Rehearsal -and $record.RestartOriginal) {
        if ((File-Hash $originalExe) -ne $record.OriginalExeSha256) { throw 'Original EXE changed during testing.' }
        if ((File-Hash (Join-Path (Split-Path -Parent $originalExe) 'data\settings.json')) -ne $record.OriginalSettingsSha256) { throw 'Original settings changed during testing; refusing automatic restart with unknown settings.' }
        $existing=@(Get-Process Netch -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $originalExe })
        if ($existing.Count -gt 0) { throw 'Original Netch was restarted outside this recovery worker; manual verification required.' }
        $resume = Start-Process -FilePath $originalExe -ArgumentList '-start' -WorkingDirectory (Split-Path -Parent $originalExe) -WindowStyle Hidden -PassThru
        $resume.Refresh()
        Save-Json 'resumed-process.json' @{Id=$resume.Id; Path=$resume.Path; StartTicks=$resume.StartTime.ToUniversalTime().Ticks.ToString()}
        Write-RecoveryLog 'Original Netch restarted; checking its own remote DNS listener.'
        $healthy=$false; $until=[DateTime]::UtcNow.AddSeconds(45)
        while ([DateTime]::UtcNow -lt $until -and -not $resume.HasExited) {
            if (Test-Reconnected $resume.Id) { Start-Sleep -Seconds 2; if (Test-Reconnected $resume.Id) { $healthy=$true; break } }
            Start-Sleep -Milliseconds 500
        }
        if (-not $healthy) {
            # Do not leave a failed automatic restart holding loopback DNS forever.
            # Terminate only this worker's exact restart, then restore saved DNS again.
            if (-not $resume.HasExited -and $resume.Path -eq $originalExe) { $resume.Kill(); $null=$resume.WaitForExit(5000) }
            Restore-Network
            Save-Json 'restored.json' @{Result='network-restored-proxy-unavailable'; ProxyReconnected=$false; ExternalAdapterRestored=$externalAdapterRestored; Utc=[DateTime]::UtcNow.ToString('o')}
            Write-RecoveryLog 'Proxy restart failed; baseline system DNS restored again. No other app was stopped.'
            exit 0
        }
        Write-RecoveryLog 'Original Netch remote DNS reconnected and answered twice.'
    }
    $result = if ($externalAdapterRestored) { 'network-restored' } else { 'netch-restored-external-adapter-pending' }
    Save-Json 'restored.json' @{ Result=$result; ProxyReconnected=(-not $record.Rehearsal -and $record.RestartOriginal); ExternalAdapterRestored=$externalAdapterRestored; Rehearsal=$record.Rehearsal; Utc=[DateTime]::UtcNow.ToString('o') }
} catch {
    Write-RecoveryLog ('Recovery failed: ' + $_.Exception.Message)
    Save-Json 'failed.json' @{ Result='restore-failed'; Error=$_.Exception.Message; Utc=[DateTime]::UtcNow.ToString('o') }
    exit 1
} finally { $owner.Dispose() }
