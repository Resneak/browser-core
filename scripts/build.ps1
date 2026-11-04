$ErrorActionPreference = "Stop"

function Assert-NativeSuccess([string]$operation) {
    if ($LASTEXITCODE -ne 0) {
        throw "$operation failed with exit code $LASTEXITCODE."
    }
}

function Assert-PinnedUpstreamManifest([string]$repository, [string]$digest) {
    Push-Location $repository
    try {
        & $pinnedPython -m browser_core upstream verify --expected-manifest-sha256 $digest | Out-Null
        Assert-NativeSuccess "Pinned upstream manifest verification"
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
$manifestText = [System.Text.Encoding]::UTF8.GetString($manifestBytes)
$manifest = $manifestText | ConvertFrom-Json
$manifestHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $manifestSha256 = ([System.BitConverter]::ToString(
        $manifestHasher.ComputeHash($manifestBytes)
    )).Replace("-", "").ToLowerInvariant()
} finally {
    $manifestHasher.Dispose()
}
Assert-PinnedUpstreamManifest $repoRoot $manifestSha256
$workspaceRaw = $env:BROWSER_CORE_WORKSPACE
$workspace = Get-BrowserCoreWorkspacePath -RawPath $workspaceRaw -RepositoryRoot $repoRoot.Path
foreach ($tool in @($pinnedPython, $pinnedGit)) {
    if ($tool.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Setup tools must be outside the selected Browser Core workspace."
    }
}
$src = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "chromium\src") -RepositoryRoot $repoRoot.Path
$depotTools = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "depot_tools") -RepositoryRoot $repoRoot.Path
$pinnedGclient = Join-Path $depotTools "gclient.bat"
$gclientFile = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "chromium\.gclient") -RepositoryRoot $repoRoot.Path
if (-not (Test-Path (Join-Path $src ".git"))) { throw "Run bootstrap.ps1 first." }
$previousPath = [Environment]::GetEnvironmentVariable('PATH')
$previousDepotToolsWinToolchain = [Environment]::GetEnvironmentVariable('DEPOT_TOOLS_WIN_TOOLCHAIN')
$previousDepotToolsUpdate = [Environment]::GetEnvironmentVariable('DEPOT_TOOLS_UPDATE')
$previousVs2026Install = [Environment]::GetEnvironmentVariable('vs2026_install')
try {
Invoke-BrowserCoreGitEnvironment {
$env:PATH = "$depotTools;$env:PATH"
$env:DEPOT_TOOLS_WIN_TOOLCHAIN = "0"
$env:DEPOT_TOOLS_UPDATE = "0"
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "Visual Studio locator is missing: $vswhere"
}
$vs2026 = (& $vswhere -latest -products '*' -version '[18.0,19.0)' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
Assert-NativeSuccess "Visual Studio 2026 discovery"
if ([string]::IsNullOrWhiteSpace($vs2026)) {
    throw "Visual Studio 2026 C++ Build Tools are required by the pinned Chromium revision."
}
$env:vs2026_install = $vs2026.Trim()
$vs2026Atl = (& $vswhere -latest -products '*' -version '[18.0,19.0)' `
    -requires Microsoft.VisualStudio.Component.VC.ATL -property installationPath)
Assert-NativeSuccess "Visual Studio 2026 ATL discovery"
if ([string]::IsNullOrWhiteSpace($vs2026Atl) -or $vs2026Atl.Trim() -ne $env:vs2026_install) {
    throw "Visual Studio 2026 ATL for the active C++ toolset is required by the pinned Chromium revision."
}
$atlHeaders = Get-ChildItem (Join-Path $env:vs2026_install "VC\Tools\MSVC") -Directory |
    ForEach-Object { Join-Path $_.FullName "atlmfc\include\atldef.h" } |
    Where-Object { Test-Path $_ }
if ($null -eq $atlHeaders -or @($atlHeaders).Count -eq 0) {
    throw "Visual Studio 2026 reports ATL installed, but atldef.h is missing."
}
$requiredSdk = "${env:ProgramFiles(x86)}\Windows Kits\10\Include\10.0.28000.0\um"
if (-not (Test-Path $requiredSdk)) {
    throw "Windows SDK 10.0.28000.0 is required by the pinned Chromium revision."
}
$out = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $src $manifest.build.output_directory) -RepositoryRoot $repoRoot.Path
$argsText = ($manifest.build.gn_args -join " ")

$mutex = Enter-BrowserCoreWorkspaceMutation $workspace

try {
    $previousBrowserCoreGitExe = [Environment]::GetEnvironmentVariable('BROWSER_CORE_GIT_EXE')
    $env:BROWSER_CORE_GIT_EXE = $pinnedGit
    Push-Location $repoRoot
    try {
        $sourceStateBefore = (& $pinnedPython -m browser_core patches state --checkout $src | ConvertFrom-Json)
        Assert-NativeSuccess "Patched checkout verification"
        [void](Get-BrowserCoreWorkspacePath -RawPath $src -RepositoryRoot $repoRoot.Path)
        if (-not (Test-Path -LiteralPath $pinnedGclient -PathType Leaf)) {
            throw "Pinned depot_tools gclient wrapper is missing: $pinnedGclient"
        }
        Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
        & $pinnedPython -m browser_core upstream verify-gclient --config $gclientFile --expected-manifest-sha256 $manifestSha256 | Out-Null
        Assert-NativeSuccess "Pinned Chromium gclient configuration verification"
        Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit
        [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGclient -RepositoryRoot $repoRoot.Path)
        Push-Location (Split-Path $src)
        try {
            Invoke-BrowserCoreGitHooksDisabled {
                & $pinnedGclient runhooks
                Assert-NativeSuccess "Chromium hooks"
            }
        } finally { Pop-Location }
        Assert-BrowserCoreNoGitWorktreeOverride $src $pinnedGit
        $pinnedGn = Join-Path $src "buildtools\win"
        $pinnedGnExe = Join-Path $pinnedGn "gn.exe"
        $pinnedAutoninja = Join-Path $depotTools "autoninja.bat"
        if (-not (Test-Path $pinnedGnExe)) {
            throw "Pinned Chromium GN binary is missing after hooks: $pinnedGn"
        }
        [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedGnExe -RepositoryRoot $repoRoot.Path)
        $env:PATH = "$pinnedGn;$depotTools;$env:PATH"
        [void](Get-BrowserCoreWorkspacePath -RawPath $out -RepositoryRoot $repoRoot.Path)
        Push-Location $src
        try {
            Assert-PinnedUpstreamManifest $repoRoot $manifestSha256
            & $pinnedGnExe gen $manifest.build.output_directory --args=$argsText
            Assert-NativeSuccess "GN generation"
            $targets = @($manifest.build.target)
            if ($null -ne $manifest.build.support_targets) {
                $targets += @($manifest.build.support_targets)
            }
            [void](Get-BrowserCoreWorkspacePath -RawPath $out -RepositoryRoot $repoRoot.Path)
            [void](Get-BrowserCoreWorkspacePath -RawPath $depotTools -RepositoryRoot $repoRoot.Path)
            if (-not (Test-Path -LiteralPath $pinnedAutoninja -PathType Leaf)) {
                throw "Pinned depot_tools autoninja wrapper is missing: $pinnedAutoninja"
            }
            [void](Get-BrowserCoreWorkspacePath -RawPath $pinnedAutoninja -RepositoryRoot $repoRoot.Path)
            Assert-PinnedUpstreamManifest $repoRoot $manifestSha256
            Assert-PinnedDepotToolsCheckout $depotTools $manifestSha256
            & $pinnedAutoninja -C $manifest.build.output_directory $targets
            Assert-NativeSuccess "Chromium build"
        } finally { Pop-Location }
        $sourceStateAfter = (& $pinnedPython -m browser_core patches state --checkout $src | ConvertFrom-Json)
        Assert-NativeSuccess "Post-build patched checkout verification"
        foreach ($field in @("revision", "patch_series_sha256", "patched_sources_sha256")) {
            if ($sourceStateAfter.$field -ne $sourceStateBefore.$field) {
                throw "Patched source state changed during the Chromium build: $field. Rebuild from a stable checkout."
            }
        }
        $executable = Join-Path $out "chrome.exe"
        & $pinnedPython -m browser_core build attest --workspace $workspace --executable $executable `
            --expected-manifest-sha256 $manifestSha256 --git-executable $pinnedGit
        Assert-NativeSuccess "Browser Core build attestation"
    } finally { Pop-Location }
} finally {
    try {
        Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe
    } finally {
        Exit-BrowserCoreWorkspaceMutation $mutex
    }
}
}
} finally {
    Restore-BrowserCoreEnvironmentVariable 'PATH' $previousPath
    Restore-BrowserCoreEnvironmentVariable 'DEPOT_TOOLS_WIN_TOOLCHAIN' $previousDepotToolsWinToolchain
    Restore-BrowserCoreEnvironmentVariable 'DEPOT_TOOLS_UPDATE' $previousDepotToolsUpdate
    Restore-BrowserCoreEnvironmentVariable 'vs2026_install' $previousVs2026Install
}
