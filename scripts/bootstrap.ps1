$ErrorActionPreference = "Stop"

function Assert-NativeSuccess([string]$operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$operation failed with exit code $LASTEXITCODE."
    }
}

function Assert-PinnedGclientConfig([string]$config, [string]$manifestSha256) {
    [void](Get-BrowserCoreWorkspacePath -RawPath $config -RepositoryRoot $repoRoot.Path)
    Push-Location $repoRoot
    try {
        & $pinnedPython -m browser_core upstream verify-gclient --config $config --expected-manifest-sha256 $manifestSha256 | Out-Null
        Assert-NativeSuccess "Pinned Chromium gclient configuration verification"
    } finally { Pop-Location }
}

function Assert-PinnedDepotToolsCheckout([string]$checkout, [string]$digest) {
    [void](Get-BrowserCoreWorkspacePath -RawPath $checkout -RepositoryRoot $repoRoot.Path)
    Push-Location $repoRoot
    try {
        & $pinnedPython -m browser_core upstream verify-depot-tools --checkout $checkout --expected-manifest-sha256 $digest --git-executable $pinnedGit | Out-Null
        Assert-NativeSuccess "Pinned depot_tools checkout verification"
    } finally { Pop-Location }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "workspace-path.ps1")
. (Join-Path $PSScriptRoot "git-hooks.ps1")
. (Join-Path $PSScriptRoot "workspace-lock.ps1")
$pinnedPython = (Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$pinnedGit = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$pinnedPython = Get-BrowserCoreWorkspacePath -RawPath $pinnedPython -RepositoryRoot $repoRoot.Path
$pinnedGit = Get-BrowserCoreWorkspacePath -RawPath $pinnedGit -RepositoryRoot $repoRoot.Path
$manifestPath = Join-Path $repoRoot "upstream.json"
$maxManifestBytes = 1024 * 1024
$manifestReader = [System.IO.BinaryReader]::new([System.IO.File]::OpenRead($manifestPath))
try {
    $manifestBytes = $manifestReader.ReadBytes($maxManifestBytes + 1)
} finally {
    $manifestReader.Dispose()
}
if ($manifestBytes.Length -gt $maxManifestBytes) {
    throw "upstream.json exceeds the 1 MiB verifier limit."
}
$manifestHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $manifestSha256 = ([System.BitConverter]::ToString(
        $manifestHasher.ComputeHash($manifestBytes)
    )).Replace("-", "").ToLowerInvariant()
} finally {
    $manifestHasher.Dispose()
}
Push-Location $repoRoot
try {
    $manifest = (& $pinnedPython -m browser_core upstream verify --expected-manifest-sha256 $manifestSha256 | ConvertFrom-Json)
    Assert-NativeSuccess "Pinned upstream manifest verification"
} finally { Pop-Location }
$workspaceRaw = $env:BROWSER_CORE_WORKSPACE
$workspace = Get-BrowserCoreWorkspacePath -RawPath $workspaceRaw -RepositoryRoot $repoRoot.Path
foreach ($tool in @($pinnedPython, $pinnedGit)) {
    if ($tool.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Setup tools must be outside the selected Browser Core workspace."
    }
}
$mutex = Enter-BrowserCoreWorkspaceMutation $workspace

try {
$previousBrowserCoreGitExe = [Environment]::GetEnvironmentVariable('BROWSER_CORE_GIT_EXE')
$previousPath = [Environment]::GetEnvironmentVariable('PATH')
$previousDepotToolsWinToolchain = [Environment]::GetEnvironmentVariable('DEPOT_TOOLS_WIN_TOOLCHAIN')
$previousDepotToolsUpdate = [Environment]::GetEnvironmentVariable('DEPOT_TOOLS_UPDATE')
$env:BROWSER_CORE_GIT_EXE = $pinnedGit
Invoke-BrowserCoreGitEnvironment {
[void](Get-BrowserCoreWorkspacePath -RawPath $workspace -RepositoryRoot $repoRoot.Path)
New-Item -ItemType Directory -Force -Path $workspace | Out-Null
$depotTools = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "depot_tools") -RepositoryRoot $repoRoot.Path
if (-not (Test-Path $depotTools)) {
    [void](Get-BrowserCoreWorkspacePath -RawPath $depotTools -RepositoryRoot $repoRoot.Path)
    & $pinnedGit -c core.hooksPath=NUL clone $manifest.depot_tools.repository $depotTools
    Assert-NativeSuccess "depot_tools clone"
}
[void](Get-BrowserCoreWorkspacePath -RawPath (Join-Path $depotTools ".git") -RepositoryRoot $repoRoot.Path)
& $pinnedGit -c core.hooksPath=NUL "--work-tree=$depotTools" -C $depotTools fetch origin $manifest.depot_tools.revision
Assert-NativeSuccess "depot_tools fetch"
[void](Get-BrowserCoreWorkspacePath -RawPath $depotTools -RepositoryRoot $repoRoot.Path)
& $pinnedGit -c core.hooksPath=NUL "--work-tree=$depotTools" -C $depotTools checkout --detach $manifest.depot_tools.revision
Assert-NativeSuccess "depot_tools checkout"
$pinnedWinTools = Join-Path $depotTools "bootstrap\win_tools.bat"
Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
[void](Get-BrowserCoreWorkspacePath -RawPath $pinnedWinTools -RepositoryRoot $repoRoot.Path)
& $pinnedWinTools
Assert-NativeSuccess "depot_tools Windows bootstrap"
$pinnedGclient = Join-Path $depotTools "gclient.bat"
if (-not (Test-Path -LiteralPath $pinnedGclient -PathType Leaf)) {
    throw "Pinned depot_tools gclient wrapper is missing: $pinnedGclient"
}
[void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGclient -RepositoryRoot $repoRoot.Path)

$env:PATH = "$depotTools;$env:PATH"
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = "0"
$env:DEPOT_TOOLS_UPDATE = "0"
$src = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "chromium\src") -RepositoryRoot $repoRoot.Path
$clientRoot = Split-Path $src
$gclientFile = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $clientRoot ".gclient") -RepositoryRoot $repoRoot.Path
if (-not (Test-Path $src)) {
    [void](Get-BrowserCoreWorkspacePath -RawPath $clientRoot -RepositoryRoot $repoRoot.Path)
    New-Item -ItemType Directory -Force -Path $clientRoot | Out-Null
    if (-not (Test-Path -LiteralPath $gclientFile)) {
        [void](Get-BrowserCoreWorkspacePath -RawPath $clientRoot -RepositoryRoot $repoRoot.Path)
        Push-Location $clientRoot
        try {
            Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
            [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGclient -RepositoryRoot $repoRoot.Path)
            Invoke-BrowserCoreGitHooksDisabled {
                & $pinnedGclient config --name src $manifest.chromium.repository
                Assert-NativeSuccess "Chromium gclient configuration"
            }
        } finally { Pop-Location }
    }
    Write-Output "Syncing the pinned shallow Chromium checkout."
    [void](Get-BrowserCoreWorkspacePath -RawPath $clientRoot -RepositoryRoot $repoRoot.Path)
    Push-Location $clientRoot
    try {
        Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
        Assert-PinnedGclientConfig $gclientFile $manifestSha256
        [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGclient -RepositoryRoot $repoRoot.Path)
        Invoke-BrowserCoreGitHooksDisabled {
            & $pinnedGclient sync --nohooks --no-history -j 4 --revision "src@$($manifest.chromium.revision)"
            Assert-NativeSuccess "Chromium pinned shallow checkout"
        }
    } finally { Pop-Location }
}
[void](Get-BrowserCoreWorkspacePath -RawPath $src -RepositoryRoot $repoRoot.Path)
if (-not (Test-Path (Join-Path $src ".git"))) {
    throw "Chromium source path exists but is not a Git checkout: $src"
}
[void](Get-BrowserCoreWorkspacePath -RawPath (Join-Path $src ".git") -RepositoryRoot $repoRoot.Path)
Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit
& $pinnedGit -c core.hooksPath=NUL "--work-tree=$src" -C $src fetch --depth=1 --no-tags origin $manifest.chromium.revision
Assert-NativeSuccess "Chromium pinned revision fetch"
[void](Get-BrowserCoreWorkspacePath -RawPath $src -RepositoryRoot $repoRoot.Path)
& $pinnedGit -c core.hooksPath=NUL "--work-tree=$src" -C $src checkout --detach $manifest.chromium.revision
Assert-NativeSuccess "Chromium pinned revision checkout"
[void](Get-BrowserCoreWorkspacePath -RawPath $clientRoot -RepositoryRoot $repoRoot.Path)
Push-Location (Split-Path $src)
try {
    Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
    Assert-PinnedGclientConfig $gclientFile $manifestSha256
    Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit
    [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGclient -RepositoryRoot $repoRoot.Path)
    Invoke-BrowserCoreGitHooksDisabled {
        & $pinnedGclient sync --nohooks --no-history -j 4 --revision "src@$($manifest.chromium.revision)"
        Assert-NativeSuccess "Chromium dependency sync"
    }
} finally { Pop-Location }

[void](Get-BrowserCoreWorkspacePath -RawPath $src -RepositoryRoot $repoRoot.Path)
[void](Get-BrowserCoreWorkspacePath -RawPath (Join-Path $src ".git") -RepositoryRoot $repoRoot.Path)
Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
Assert-PinnedGclientConfig $gclientFile $manifestSha256
Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit
$finalRevision = @(& $pinnedGit -c core.hooksPath=NUL "--work-tree=$src" -C $src rev-parse --verify HEAD)
Assert-NativeSuccess "Final Chromium checkout revision verification"
if ($finalRevision.Count -ne 1 -or $finalRevision[0].Trim() -cne $manifest.chromium.revision) {
    throw "Chromium checkout revision changed during dependency sync."
}
Write-Output "Pinned Chromium workspace ready at $src"
}
} finally {
    try {
        Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe
        Restore-BrowserCoreEnvironmentVariable 'PATH' $previousPath
        Restore-BrowserCoreEnvironmentVariable 'DEPOT_TOOLS_WIN_TOOLCHAIN' $previousDepotToolsWinToolchain
        Restore-BrowserCoreEnvironmentVariable 'DEPOT_TOOLS_UPDATE' $previousDepotToolsUpdate
    } finally {
        Exit-BrowserCoreWorkspaceMutation $mutex
    }
}
