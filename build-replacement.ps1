param([string]$Dotnet = '', [switch]$NoRestore, [string]$SocksProxy = '', [switch]$OfflineCores, [string]$OutputDirectory = 'artifacts/replacement')
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
& (Join-Path $taskRoot 'prepare-cores.ps1') -SocksProxy $SocksProxy -Offline:$OfflineCores
if (-not $Dotnet) {
    $taskBundledSdk = Join-Path $taskRoot '.build\dotnet\dotnet.exe'
    $Dotnet = if (Test-Path -LiteralPath $taskBundledSdk) { $taskBundledSdk } else { 'dotnet' }
}
$taskPublish = Join-Path $taskRoot '.build\publish-replacement'
$taskOutput = [IO.Path]::GetFullPath((Join-Path $taskRoot $OutputDirectory))
if (-not $taskOutput.StartsWith($taskRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'OutputDirectory must stay inside the workspace.' }
New-Item -ItemType Directory -Path $taskPublish, $taskOutput -Force | Out-Null
$env:DOTNET_CLI_HOME = Join-Path $taskRoot '.build\cli'
$env:NUGET_PACKAGES = Join-Path $taskRoot '.build\packages'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
$taskSdkOptions = @()
$taskWindowsSdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
if (Test-Path -LiteralPath $taskWindowsSdk) {
    # Use the installed SDK directly instead of enumerating per-user SDK locations.
    $taskSdkOptions += "-p:TargetPlatformSdkRootOverride=$taskWindowsSdk"
    $taskSdkOptions += '-p:TargetPlatformDisplayName=Windows'
}
if ($NoRestore) { $taskSdkOptions += '--no-restore' }
& $Dotnet publish (Join-Path $taskRoot 'Netch\Netch.csproj') -c Release -r win-x64 --self-contained true `
    -p:Platform=x64 -p:BundleProxyCores=true -p:PublishSingleFile=true -p:PublishTrimmed=false -p:PublishReadyToRun=false `
    -p:IncludeNativeLibrariesForSelfExtract=true @taskSdkOptions -o $taskPublish -v:minimal
if ($LASTEXITCODE -ne 0) { throw 'Publish failed; no replacement was copied.' }
$taskExecutable = Join-Path $taskOutput 'Netch.exe'
Copy-Item -LiteralPath (Join-Path $taskPublish 'Netch.exe') -Destination $taskExecutable -Force
$taskHash = (Get-FileHash -LiteralPath $taskExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $taskOutput 'Netch.exe.sha256'), "$taskHash  Netch.exe`n")
$taskVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($taskExecutable).ProductVersion
$taskRelease = @{ Version=$taskVersion; Sha256=$taskHash; AutoConnect=$true }
[IO.File]::WriteAllText((Join-Path $taskOutput 'Netch.release.json'), ($taskRelease | ConvertTo-Json))
Get-Item -LiteralPath $taskExecutable | Select-Object FullName, Length
Write-Output "SHA256: $taskHash"
