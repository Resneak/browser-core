if (-not ('BrowserCoreWorkspacePathNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class BrowserCoreWorkspacePathNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string path, uint access, uint share, IntPtr security, uint disposition,
        uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandle(
        SafeFileHandle handle, StringBuilder path, uint capacity, uint flags);
}
'@
}

function Get-BrowserCoreFinalExistingPath([string]$path) {
    $handle = [BrowserCoreWorkspacePathNative]::CreateFile(
        $path, 0, 7, [IntPtr]::Zero, 3, 0x02000000, [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        $handle.Dispose()
        throw "BROWSER_CORE_WORKSPACE path cannot be checked."
    }
    try {
        $buffer = [System.Text.StringBuilder]::new(32768)
        $length = [BrowserCoreWorkspacePathNative]::GetFinalPathNameByHandle(
            $handle, $buffer, [uint32]$buffer.Capacity, 0
        )
        if ($length -eq 0 -or $length -ge $buffer.Capacity) {
            throw "BROWSER_CORE_WORKSPACE path cannot be checked."
        }
        $resolved = $buffer.ToString()
    } finally {
        $handle.Dispose()
    }
    if (-not $resolved.StartsWith('\\?\', [System.StringComparison]::Ordinal)) {
        throw "BROWSER_CORE_WORKSPACE path cannot be checked."
    }
    $resolved = $resolved.Substring(4)
    if ($resolved -notmatch '^[A-Za-z]:\\') {
        throw "BROWSER_CORE_WORKSPACE must resolve to a drive-letter path."
    }
    return $resolved
}

function Get-BrowserCoreWorkspacePath {
    param(
        [string]$RawPath,
        [string]$RepositoryRoot
    )

    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        throw "Set BROWSER_CORE_WORKSPACE to an absolute drive-letter path outside the repository."
    }
    if (
        $RawPath -ne $RawPath.Trim() -or
        $RawPath -notmatch '^[A-Za-z]:[\\/]' -or
        $RawPath -match '[\x00-\x1f\x7f]' -or
        $RawPath.Substring(2) -match '[:<>"|?*]' -or
        $RawPath.Substring(3) -match '(?:^|[\\/])[^\\/]*[. ](?:[\\/]|$)' -or
        $RawPath.Contains('[') -or
        $RawPath.Contains(']')
    ) {
        throw "BROWSER_CORE_WORKSPACE must be an absolute drive-letter path."
    }

    $workspace = [System.IO.Path]::GetFullPath($RawPath)
    $driveRoot = [System.IO.Path]::GetPathRoot($workspace)
    $repository = [System.IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\')
    $workspaceName = $workspace.TrimEnd('\')
    if ($workspaceName.Equals($driveRoot.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "BROWSER_CORE_WORKSPACE must name a directory below the drive root."
    }

    $ancestors = [System.Collections.Generic.List[string]]::new()
    $cursor = $workspaceName
    $driveName = $driveRoot
    while (-not $cursor.Equals($driveName, [System.StringComparison]::OrdinalIgnoreCase)) {
        $ancestors.Add($cursor)
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent.Equals($cursor, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "BROWSER_CORE_WORKSPACE path cannot be checked."
        }
        $cursor = $parent
    }
    $deepestExisting = $driveRoot
    for ($index = $ancestors.Count - 1; $index -ge 0; $index--) {
        $entry = $null
        try {
            $entry = Get-Item -LiteralPath $ancestors[$index] -Force -ErrorAction Stop
        } catch [System.Management.Automation.ItemNotFoundException] {}
        if ($null -ne $entry -and ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "BROWSER_CORE_WORKSPACE must not traverse a filesystem link."
        }
        if ($null -ne $entry) {
            if ($index -gt 0 -and -not $entry.PSIsContainer) {
                throw "BROWSER_CORE_WORKSPACE path cannot be checked."
            }
            $deepestExisting = $ancestors[$index]
        }
    }
    $canonicalRepository = (Get-BrowserCoreFinalExistingPath $repository).TrimEnd('\')
    $canonicalExisting = Get-BrowserCoreFinalExistingPath $deepestExisting
    $suffix = $workspaceName.Substring($deepestExisting.Length).TrimStart('\')
    $canonicalWorkspace = if ($suffix) {
        [System.IO.Path]::GetFullPath((Join-Path $canonicalExisting $suffix)).TrimEnd('\')
    } else {
        $canonicalExisting.TrimEnd('\')
    }
    $repositoryPrefix = $canonicalRepository + '\'
    $workspacePrefix = $canonicalWorkspace + '\'
    if (
        $canonicalWorkspace.Equals($canonicalRepository, [System.StringComparison]::OrdinalIgnoreCase) -or
        $canonicalWorkspace.StartsWith($repositoryPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        $canonicalRepository.StartsWith($workspacePrefix, [System.StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "BROWSER_CORE_WORKSPACE must be outside the research repository."
    }
    try {
        $fileSystem = ([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($canonicalWorkspace))).DriveFormat
    } catch {
        throw "BROWSER_CORE_WORKSPACE drive format could not be checked."
    }
    if ($fileSystem -ne 'NTFS') {
        throw "BROWSER_CORE_WORKSPACE must be on NTFS; $driveRoot is $fileSystem."
    }
    return $canonicalWorkspace
}
