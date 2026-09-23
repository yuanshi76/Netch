param (
	[Parameter()]
	[ValidateSet('Debug', 'Release')]
	[string]
	$Configuration = 'Release',

	[Parameter()]
	[ValidateNotNullOrEmpty()]
	[string]
	$OutputPath = 'release',

	[Parameter()]
	[bool]
	$SelfContained = $True,

	[Parameter()]
	[bool]
	$PublishSingleFile = $True,

	[Parameter()]
	[bool]
	$PublishReadyToRun = $False
)

Push-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

$ErrorActionPreference = 'Stop'
$taskBuildRoot = [IO.Path]::GetFullPath($PWD.Path).TrimEnd('\')
$taskOutput = [IO.Path]::GetFullPath((Join-Path $taskBuildRoot $OutputPath))
if (-not $taskOutput.StartsWith($taskBuildRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputPath must be a child directory inside this project.'
}
# Preserve existing directories; building must never delete an arbitrary output tree.
New-Item -ItemType Directory -Path $taskOutput -Force | Out-Null

Push-Location $OutputPath
New-Item -ItemType Directory -Name 'bin' -Force | Out-Null
cp -Recurse -Force '..\Storage\i18n' '.'  | Out-Null
cp -Recurse -Force '..\Storage\mode' '.'  | Out-Null
cp -Recurse -Force '..\Storage\stun.txt' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\nfdriver.sys' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\aiodns.conf' 'bin'  | Out-Null
#cp -Recurse -Force '..\Storage\GeoLite2-Country.mmdb' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\tun2socks-windows-amd64-v3.exe' 'bin'  | Out-Null
cp -Recurse -Force '..\Storage\README.md' 'bin'  | Out-Null
Pop-Location

if ( -Not ( Test-Path '.\Other\release' ) ) {
	.\Other\build.ps1
	if ( -Not $? ) {
		exit $lastExitCode
	}
}
cp -Force '.\Other\release\*.bin' "$OutputPath\bin"
cp -Force '.\Other\release\*.dll' "$OutputPath\bin"
cp -Force '.\Other\release\*.exe' "$OutputPath\bin"
cp -Force '.\Other\release\GeoLite2-Country.mmdb' "$OutputPath\bin"

& {
	Write-Host
	Write-Host 'Building Netch'

	dotnet publish `
		-c $Configuration `
		-r 'win-x64' `
		-p:Platform='x64' `
		-p:SelfContained=$SelfContained `
		-p:PublishTrimmed=$False `
		-p:PublishSingleFile=$PublishSingleFile `
		-p:PublishReadyToRun=$PublishReadyToRun `
		-p:PublishReadyToRunShowWarnings=$PublishReadyToRun `
		-p:IncludeNativeLibrariesForSelfExtract=$SelfContained `
		-o ".\Netch\bin\$Configuration" `
		'.\Netch\Netch.csproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\Netch\bin\$Configuration\Netch.exe" $OutputPath

& {
	Write-Host
	Write-Host 'Building Redirector'

	msbuild `
		-property:Configuration=$Configuration `
		-property:Platform=x64 `
		'.\Redirector\Redirector.vcxproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\Redirector\bin\$Configuration\nfapi.dll"      "$OutputPath\bin"
cp -Force ".\Redirector\bin\$Configuration\Redirector.bin" "$OutputPath\bin"

& {
	Write-Host
	Write-Host 'Building RouteHelper'

	msbuild `
		-property:Configuration=$Configuration `
		-property:Platform=x64 `
		'.\RouteHelper\RouteHelper.vcxproj'
	if ( -Not $? ) { exit $lastExitCode }
}
cp -Force ".\RouteHelper\bin\$Configuration\RouteHelper.bin" "$OutputPath\bin"

if ( $Configuration.Equals('Release') ) {
	Get-ChildItem -LiteralPath $taskOutput -Filter '*.pdb' | Remove-Item -Force
	Get-ChildItem -LiteralPath $taskOutput -Filter '*.xml' | Remove-Item -Force
}

Pop-Location
exit 0
