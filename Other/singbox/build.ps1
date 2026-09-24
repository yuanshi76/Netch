$ErrorActionPreference = 'Stop'
# Cores are embedded in Netch.exe and deployed into versioned directories at runtime.
# Keep this legacy build entry point pinned to the same verified archives.
& (Join-Path $PSScriptRoot '..\..\prepare-cores.ps1')
