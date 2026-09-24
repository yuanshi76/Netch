# Run with Windows PowerShell 5.1, the same runtime used by the independent worker.
# Extract the real recovery functions, mock all network/system mutations, and run
# the production branch. This catches regressions that file-only rehearsal misses.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$source=Join-Path $PSScriptRoot 'Watchdog.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw 'Watchdog parse errors'}
$functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]},$false)
foreach($name in @('Restore-Network','Stop-RecordedProcess','Restore-PausedAdapter','Try-RestorePausedAdapter')) {
    $definition=$functions | Where-Object {$_.Name -eq $name}
    if(@($definition).Count -ne 1){throw 'Recovery function missing'}
    Invoke-Expression $definition.Extent.Text
}
$workspace=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$stateDirectory=Join-Path $workspace ('.build\network-acceptance\unit-'+[Guid]::NewGuid().ToString('N'))
$testDirectory=Join-Path $stateDirectory 'test'
$null=New-Item -ItemType Directory -Path $testDirectory -Force
$script:removed=0; $script:cleared=0; $script:lookups=0
function Write-RecoveryLog([string]$message) { }
function Run-Netsh { throw 'Unexpected DNS mutation in empty-baseline test' }
function Get-NetAdapter { $script:lookups++; [PSCustomObject]@{InterfaceGuid=[Guid]'20214ad5-1d95-4cc1-9233-d850d2c9cf9c';ifIndex=14} }
function Get-NetRoute { @() }
function Remove-NetRoute { $script:removed++ }
function Get-NetFirewallRule { @() }
function Get-NetFirewallApplicationFilter { throw 'Unexpected firewall application access' }
function Remove-NetFirewallRule { throw 'Unexpected firewall deletion' }
function Clear-DnsClientCache { $script:cleared++ }
function New-Object {
    param([Parameter(Position=0)][string]$TypeName,[string]$ComObject)
    if($ComObject -eq 'HNetCfg.FwPolicy2') { return [PSCustomObject]@{Rules=@()} }
    if($TypeName -eq 'System.Collections.Generic.List[string]') { return ,([Collections.Generic.List[string]]::new()) }
    throw 'Unexpected object construction'
}
$record=[PSCustomObject]@{Rehearsal=$false;Dns=@()}
'[]' | Set-Content -LiteralPath (Join-Path $stateDirectory 'owned-routes.json') -Encoding UTF8
Restore-Network
if($script:lookups -ne 0 -or $script:removed -ne 0 -or $script:cleared -ne 1){throw 'Empty list did not remain empty'}
'PASS production recovery branch accepts empty route list in Windows PowerShell'
$routes=@(
    @{InterfaceId='{20214AD5-1D95-4CC1-9233-D850D2C9CF9C}';DestinationPrefix='198.18.0.0/15';NextHop='192.0.2.1';Metric=1},
    @{InterfaceId='20214ad5-1d95-4cc1-9233-d850d2c9cf9c';DestinationPrefix='192.0.2.0/24';NextHop='192.0.2.1';Metric=1}
)
ConvertTo-Json -InputObject $routes | Set-Content -LiteralPath (Join-Path $stateDirectory 'owned-routes.json') -Encoding UTF8
Restore-Network
if($script:lookups -ne 2){throw 'Multiple entries were treated as one object'}
'PASS route entries iterate individually and GUID braces are normalized'
$journalDirectory=Join-Path $testDirectory 'host\data'
$null=New-Item -ItemType Directory -Path $journalDirectory -Force
'[]' | Set-Content -LiteralPath (Join-Path $stateDirectory 'owned-routes.json') -Encoding UTF8
ConvertTo-Json -InputObject @($routes[0]) | Set-Content -LiteralPath (Join-Path $journalDirectory 'tun-owned-routes.json') -Encoding UTF8
Restore-Network
if($script:lookups -ne 3){throw 'Production TUN journal was not consumed'}
'PASS independent recovery consumes the durable production TUN journal'
$processFile=Join-Path $stateDirectory 'owned-processes.json'
'[]' | Set-Content -LiteralPath $processFile -Encoding UTF8
$processEntries=Get-Content -LiteralPath $processFile -Raw | ConvertFrom-Json
$count=0; foreach($entry in $processEntries){$count++}
if($count -ne 0){throw 'Empty process array was treated as a process'}
'PASS missing host after stop still allows recovery from an empty process list'
# Manual takeover must be checked before the first Restore-Network call in main.
$text=Get-Content -LiteralPath $source -Raw
$main=$text.Substring($text.IndexOf("Write-RecoveryLog 'Deadline/manual recovery triggered locally.'"))
if($main.IndexOf("Result='user-restarted-network-untouched'") -lt 0 -or $main.IndexOf("Result='user-restarted-network-untouched'") -gt $main.IndexOf('try { Restore-Network;')){throw 'Manual restart guard is after network mutation'}
'PASS manual takeover guard precedes network restoration (static ordering check)'
$script:adapterState='Disabled'; $script:enableCalls=0
function Get-NetAdapter {
    [PSCustomObject]@{InterfaceGuid=[Guid]'20214ad5-1d95-4cc1-9233-d850d2c9cf9c';Name='FastLink';Status=$script:adapterState;ifIndex=14}
}
function Enable-NetAdapter {
    param([Parameter(ValueFromPipeline=$true)]$InputObject,[switch]$Confirm)
    process { $script:enableCalls++; $script:adapterState='Up' }
}
$record | Add-Member NoteProperty FastLinkAdapter ([PSCustomObject]@{Id='20214ad5-1d95-4cc1-9233-d850d2c9cf9c';Name='FastLink'})
Restore-PausedAdapter
if($script:enableCalls -ne 0){throw 'Unrequested adapter pause was restored'}
$null=New-Item -ItemType File -Path (Join-Path $stateDirectory 'fastlink-pause-requested')
Restore-PausedAdapter; Restore-PausedAdapter
if($script:enableCalls -ne 1 -or $script:adapterState -ne 'Up'){throw 'Adapter restoration was not idempotent'}
'PASS authorized adapter restoration requires write-ahead marker and is idempotent'
$record.FastLinkAdapter.Id='105c3e68-a2a6-4a52-b96e-8302c95678bb'
$rejected=$false
try { Restore-PausedAdapter } catch { $rejected=$true }
if(-not $rejected -or $script:enableCalls -ne 1){throw 'Changed adapter identity was accepted'}
'PASS adapter restoration refuses a changed GUID'
$script:pending=$false
function Save-Json([string]$name, $value) { if ($name -eq 'adapter-restore-pending.json') { $script:pending=$true } }
if ((Try-RestorePausedAdapter) -or -not $script:pending) { throw 'External adapter failure was not recorded as pending' }
$record.Dns=@([PSCustomObject]@{Id=$record.FastLinkAdapter.Id;V6=$false;StaticServers=@()})
$before=$script:cleared
Restore-Network
if ($script:cleared -ne $before+1) { throw 'Missing external adapter skipped remaining network cleanup' }
'PASS missing external adapter is reported and cannot abort remaining DNS/rule cleanup'
$record.Dns=@([PSCustomObject]@{Id='ee8d5df5-3b88-4c77-a717-286c5a6211e5';V6=$false;StaticServers=@()})
$rejected=$false
try { Restore-Network } catch { $rejected=$true }
if (-not $rejected) { throw 'Unrelated missing adapter was silently ignored' }
'PASS only the recorded absent external adapter may defer DNS restoration'
