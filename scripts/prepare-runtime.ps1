param([Parameter(Mandatory=$true)][string]$RuntimeDirectory)
$ErrorActionPreference = 'Stop'
$runtimePath = (Resolve-Path -LiteralPath $RuntimeDirectory).Path
if (-not (Test-Path -LiteralPath (Join-Path $runtimePath 'browser-core-build.json') -PathType Leaf)) {
    throw 'Select the extracted Browser Core runtime directory containing browser-core-build.json.'
}
if (-not (Test-Path -LiteralPath (Join-Path $runtimePath 'chrome.exe') -PathType Leaf)) {
    throw 'The selected runtime does not contain chrome.exe.'
}
Get-ChildItem -LiteralPath $runtimePath -Recurse -File | Unblock-File
# Well-known sandbox group SIDs work independently of the Windows display language.
& icacls.exe $runtimePath /grant '*S-1-15-2-1:(OI)(CI)(RX)' '*S-1-15-2-2:(OI)(CI)(RX)' /T /C /Q
if ($LASTEXITCODE -ne 0) { throw 'Could not grant sandbox read and execute access to every runtime file.' }
Write-Output 'Runtime permissions prepared. Next run browser-core doctor --executable <runtime>\chrome.exe.'
