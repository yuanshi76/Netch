param([string]$NetchDirectory = 'D:\Netch',[ValidateSet('FullProcess','Tun')][string]$AcceptanceMode='FullProcess',[switch]$TemporarilyDisableFastLink)
# Read-only system inspection. Writes a private local recovery plan, never arms it.
$ErrorActionPreference = 'Stop'
if ($TemporarilyDisableFastLink) { throw 'Adapter-disable acceptance is retired: the installed Wintun can delete disabled adapters. No network changes were made.' }
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$originalDirectory = (Resolve-Path -LiteralPath $NetchDirectory).Path
$originalExe = Join-Path $originalDirectory 'Netch.exe'
$session = Join-Path $workspace ('.build\network-acceptance\session-' + [Guid]::NewGuid().ToString('N'))
$testDirectory = Join-Path $session 'test'
$null = New-Item -ItemType Directory -Path $testDirectory -Force
# Baselines may include the user's node credentials; inherit no broad read access.
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @([Security.Principal.WindowsIdentity]::GetCurrent().User, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
}
Set-Acl -LiteralPath $session -AclObject $acl
$journalFile = Join-Path $originalDirectory 'data\dns-protection.json'
$savedAdapters = @()
if (Test-Path -LiteralPath $journalFile) {
    $journal = Get-Content -LiteralPath $journalFile -Raw | ConvertFrom-Json
    if ($journal.Version -ne 1) { throw 'Unknown original DNS journal version.' }
    $savedAdapters = @($journal.Adapters)
    Copy-Item -LiteralPath $journalFile -Destination (Join-Path $session 'original-dns-protection.json')
}
$dns = @()
foreach ($adapter in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($adapter.NetworkInterfaceType -eq 'Loopback' -or $adapter.Name -eq 'Netch' -or $adapter.OperationalStatus -ne 'Up') { continue }
    foreach ($v6 in @($false,$true)) {
        $component = if ($v6) { [Net.NetworkInformation.NetworkInterfaceComponent]::IPv6 } else { [Net.NetworkInformation.NetworkInterfaceComponent]::IPv4 }
        if (-not $adapter.Supports($component)) { continue }
        $family = if ($v6) { 'Tcpip6' } else { 'Tcpip' }
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$family\Parameters\Interfaces\$($adapter.Id)")
        try { $raw = if ($null -eq $key) { '' } else { [string]$key.GetValue('NameServer','') } } finally { if ($null -ne $key) { $key.Dispose() } }
        $addresses = @($raw -split '[, ;]+' | Where-Object { $_ })
        $loopback = if ($v6) { '::1' } else { '127.0.0.1' }
        if ($addresses.Count -eq 1 -and $addresses[0] -eq $loopback) {
            $saved = @($savedAdapters | Where-Object { $_.Id -eq $adapter.Id -and $_.V6 -eq $v6 })
            if ($saved.Count -ne 1) { throw 'Loopback DNS has no unique recovery baseline; do not test.' }
            $addresses = @($saved[0].StaticServers)
        }
        $dns += @{ Id=$adapter.Id; V6=$v6; StaticServers=$addresses }
    }
}
$routes = @(Get-NetRoute | Select-Object DestinationPrefix,InterfaceIndex,InterfaceAlias,NextHop,RouteMetric,AddressFamily)
ConvertTo-Json -InputObject @($routes) -Depth 5 | Set-Content -LiteralPath (Join-Path $session 'baseline-routes.json') -Encoding UTF8
$settings = Join-Path $originalDirectory 'data\settings.json'
Copy-Item -LiteralPath $settings -Destination (Join-Path $session 'original-settings.json')
foreach ($file in @('owned-processes.json','owned-routes.json')) { '[]' | Set-Content -LiteralPath (Join-Path $session $file) -Encoding UTF8 }
$hash = (Get-FileHash -LiteralPath $originalExe).Hash
$artifact = Join-Path $workspace 'artifacts\replacement\Netch.exe'
$releaseFile=Join-Path $workspace 'artifacts\replacement\Netch.release.json'
$release=if(Test-Path -LiteralPath $releaseFile) { Get-Content -LiteralPath $releaseFile -Raw | ConvertFrom-Json } else { $null }
$resumeSupported = $null -ne $release -and $release.Version -eq '1.9.11-dns-preview.9' -and $release.AutoConnect -and
    $hash -eq $release.Sha256 -and (Test-Path -LiteralPath $artifact) -and $hash -eq (Get-FileHash -LiteralPath $artifact).Hash
$original = @(Get-Process Netch -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $originalExe })
if ($original.Count -ne 1) { throw 'Exactly one original Netch must be connected before preparing acceptance.' }
$originalProcesses = @($original[0])
foreach ($child in @(Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $original[0].Id))) {
    if ($child.ExecutablePath -and $child.ExecutablePath.StartsWith($originalDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) { $originalProcesses += Get-Process -Id $child.ProcessId }
}
$identities = @($originalProcesses | ForEach-Object { @{ Id=$_.Id; Path=$_.Path; StartTicks=$_.StartTime.ToUniversalTime().Ticks.ToString() } })
$plan = @{ Version=1; Rehearsal=$false; TimeoutSeconds=180; AcceptanceMode=$AcceptanceMode; TestDirectory=$testDirectory; OriginalExe=$originalExe; OriginalExeSha256=$hash; OriginalSettingsSha256=(Get-FileHash -LiteralPath $settings).Hash; OriginalProcesses=$identities; RestartOriginal=$resumeSupported; Dns=$dns; PreparedUtc=[DateTime]::UtcNow.ToString('o') }
$plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $session 'plan.json') -Encoding UTF8
'Recovery plan prepared, not armed: ' + $session
if (-not $resumeSupported) { 'Automatic reconnect is not authorized for this EXE version; install the verified preview.9 build before live acceptance.' }
[PSCustomObject]@{ PlanPath=(Join-Path $session 'plan.json') }
