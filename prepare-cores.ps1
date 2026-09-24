param([string]$SocksProxy = '', [switch]$Offline)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskCache = Join-Path $taskRoot '.build\cores'
$taskManifest = Get-Content -LiteralPath (Join-Path $taskRoot 'Storage\cores.lock.json') -Raw | ConvertFrom-Json
New-Item -ItemType Directory -Path $taskCache -Force | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem

foreach ($taskCore in $taskManifest.cores) {
    $taskArchive = Join-Path $taskCache ($taskCore.id + '-' + $taskCore.version + '.zip')
    if (-not (Test-Path -LiteralPath $taskArchive)) {
        if ($Offline) { throw "Missing pinned core archive: $taskArchive" }
        $taskDownload = $taskArchive + '.' + [Guid]::NewGuid().ToString('N') + '.download'
        try {
            $taskCurlArgs = @('--fail', '--silent', '--show-error', '--location', '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15', '--max-time', '240')
            if ($SocksProxy) { $taskCurlArgs += @('--socks5-hostname', $SocksProxy) }
            & curl.exe @taskCurlArgs --output $taskDownload $taskCore.url
            if ($LASTEXITCODE -ne 0) { throw "Could not download $($taskCore.id) $($taskCore.version)" }
            if ((Get-FileHash -LiteralPath $taskDownload -Algorithm SHA256).Hash -ne $taskCore.archiveSha256) {
                throw "Archive checksum mismatch: $($taskCore.id)"
            }
            Move-Item -LiteralPath $taskDownload -Destination $taskArchive
        }
        finally { if (Test-Path -LiteralPath $taskDownload) { Remove-Item -LiteralPath $taskDownload -Force } }
    }
    if ((Get-FileHash -LiteralPath $taskArchive -Algorithm SHA256).Hash -ne $taskCore.archiveSha256) {
        throw "Cached archive checksum mismatch: $taskArchive"
    }
    $taskZip = [IO.Compression.ZipFile]::OpenRead($taskArchive)
    try {
        foreach ($taskFile in $taskCore.files) {
            $taskEntry = $taskZip.GetEntry($taskFile.entry)
            if (-not $taskEntry) { throw "Missing archive entry: $($taskFile.entry)" }
            $taskStream = $taskEntry.Open()
            $taskSha = [Security.Cryptography.SHA256]::Create()
            try { $taskHash = [BitConverter]::ToString($taskSha.ComputeHash($taskStream)).Replace('-', '').ToLowerInvariant() }
            finally { $taskStream.Dispose(); $taskSha.Dispose() }
            if ($taskHash -ne $taskFile.sha256) { throw "Payload checksum mismatch: $($taskFile.entry)" }
        }
    }
    finally { $taskZip.Dispose() }
    Write-Output "Verified $($taskCore.id) $($taskCore.version)"
}

# Generate exact resource paths from the lock file, even if other versions are cached.
$taskItems = foreach ($taskCore in $taskManifest.cores) {
    $taskArchive = [Security.SecurityElement]::Escape((Join-Path $taskCache ($taskCore.id + '-' + $taskCore.version + '.zip')))
    '    <EmbeddedResource Include="' + $taskArchive + '" LogicalName="Netch.BundledCores.' + $taskCore.id + '.zip" />'
}
[IO.File]::WriteAllText((Join-Path $taskCache 'cores.props'), "<Project>`n  <ItemGroup>`n" + ($taskItems -join "`n") + "`n  </ItemGroup>`n</Project>`n")
