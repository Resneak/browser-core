$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot ".."))
. (Join-Path $PSScriptRoot "workspace-path.ps1")
. (Join-Path $PSScriptRoot "git-hooks.ps1")
. (Join-Path $PSScriptRoot "workspace-lock.ps1")
$pinnedPython = (Get-Command python.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$pinnedGit = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$pinnedPython = Get-BrowserCoreWorkspacePath -RawPath $pinnedPython -RepositoryRoot $repoRoot.Path
$pinnedGit = Get-BrowserCoreWorkspacePath -RawPath $pinnedGit -RepositoryRoot $repoRoot.Path
$workspaceRaw = $env:BROWSER_CORE_WORKSPACE
$workspace = Get-BrowserCoreWorkspacePath -RawPath $workspaceRaw -RepositoryRoot $repoRoot.Path
foreach ($tool in @($pinnedPython, $pinnedGit)) {
    if ($tool.StartsWith($workspace + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Setup tools must be outside the selected Browser Core workspace."
    }
}
$checkout = Get-BrowserCoreWorkspacePath -RawPath (Join-Path $workspace "chromium\src") -RepositoryRoot $repoRoot.Path
$previousBrowserCoreGitExe = [Environment]::GetEnvironmentVariable('BROWSER_CORE_GIT_EXE')
$mutex = Enter-BrowserCoreWorkspaceMutation $workspace
try {
    Push-Location $repoRoot
    try {
        $env:BROWSER_CORE_GIT_EXE = $pinnedGit
        Invoke-BrowserCoreGitEnvironment {
            & $pinnedPython -m browser_core patches verify
            if ($LASTEXITCODE -ne 0) { throw "Patch manifest verification failed with exit code $LASTEXITCODE." }
            [void](Get-BrowserCoreWorkspacePath -RawPath $checkout -RepositoryRoot $repoRoot.Path)
            & $pinnedPython -m browser_core patches apply --checkout $checkout --check
            if ($LASTEXITCODE -ne 0) { throw "Patch preflight failed with exit code $LASTEXITCODE." }
            [void](Get-BrowserCoreWorkspacePath -RawPath $checkout -RepositoryRoot $repoRoot.Path)
            & $pinnedPython -m browser_core patches apply --checkout $checkout
            if ($LASTEXITCODE -ne 0) { throw "Patch application failed with exit code $LASTEXITCODE." }
            & $pinnedPython -m browser_core patches state --checkout $checkout
            if ($LASTEXITCODE -ne 0) { throw "Patched checkout verification failed with exit code $LASTEXITCODE." }
        }
    } finally {
        Pop-Location
    }
} finally {
    try {
        Restore-BrowserCoreEnvironmentVariable 'BROWSER_CORE_GIT_EXE' $previousBrowserCoreGitExe
    } finally {
        Exit-BrowserCoreWorkspaceMutation $mutex
    }
}
