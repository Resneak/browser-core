function Enter-BrowserCoreWorkspaceMutation {
    param([Parameter(Mandatory = $true)][string]$Workspace)

    if ([string]::IsNullOrWhiteSpace($Workspace)) {
        throw "A Browser Core workspace is required for the mutation lock."
    }
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $workspaceHash = ([System.BitConverter]::ToString(
            $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Workspace.ToLowerInvariant()))
        )).Replace("-", "")
    } finally {
        $hasher.Dispose()
    }

    $mutex = [System.Threading.Mutex]::new($false, "Local\BrowserCoreWorkspace_$workspaceHash")
    $ownsMutex = $false
    try {
        try {
            $ownsMutex = $mutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $ownsMutex = $true
        }
        if (-not $ownsMutex) {
            throw "Another Browser Core operation already owns this workspace: $Workspace"
        }
        return $mutex
    } catch {
        if ($ownsMutex) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
        throw
    }
}

function Exit-BrowserCoreWorkspaceMutation {
    param([Parameter(Mandatory = $true)][System.Threading.Mutex]$Mutex)

    try {
        $Mutex.ReleaseMutex()
    } finally {
        $Mutex.Dispose()
    }
}
