function Restore-BrowserCoreEnvironmentVariable {
    param([string]$Name, $Value)

    if ($null -eq $Value) {
        Remove-Item -LiteralPath ("Env:" + $Name) -ErrorAction SilentlyContinue
    } else {
        [Environment]::SetEnvironmentVariable($Name, [string]$Value)
    }
}

function Assert-BrowserCoreNoGitWorktreeOverride {
    param([string]$Checkout, [string]$GitExecutable)

    $values = @(& $GitExecutable "--work-tree=$Checkout" -C $Checkout config --get-all core.worktree)
    if ($LASTEXITCODE -ne 1 -or $values.Count -ne 0) {
        throw "Chromium checkout core.worktree override is not allowed."
    }
}

function Invoke-BrowserCoreGitHooksDisabled {
    param([scriptblock]$Action)

    if ($null -eq $Action) {
        throw "A Git operation is required."
    }
    $previousCount = [Environment]::GetEnvironmentVariable('GIT_CONFIG_COUNT')
    if ([string]::IsNullOrEmpty($previousCount)) {
        $count = 0
    } elseif ($previousCount -cmatch '^(?:0|[1-9][0-9]?)$' -and [int]$previousCount -lt 64) {
        $count = [int]$previousCount
    } else {
        throw "GIT_CONFIG_COUNT is invalid for the scoped Git hook setting."
    }

    $keyName = "GIT_CONFIG_KEY_$count"
    $valueName = "GIT_CONFIG_VALUE_$count"
    $previousKey = [Environment]::GetEnvironmentVariable($keyName)
    $previousValue = [Environment]::GetEnvironmentVariable($valueName)
    try {
        [Environment]::SetEnvironmentVariable($keyName, 'core.hooksPath')
        [Environment]::SetEnvironmentVariable($valueName, 'NUL')
        [Environment]::SetEnvironmentVariable('GIT_CONFIG_COUNT', [string]($count + 1))
        & $Action
    } finally {
        Restore-BrowserCoreEnvironmentVariable 'GIT_CONFIG_COUNT' $previousCount
        Restore-BrowserCoreEnvironmentVariable $keyName $previousKey
        Restore-BrowserCoreEnvironmentVariable $valueName $previousValue
    }
}

function Invoke-BrowserCoreGitEnvironment {
    param([scriptblock]$Action)

    if ($null -eq $Action) {
        throw "A Git operation is required."
    }
    $previous = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
        $name = [string]$entry.Key
        if ($name.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase)) {
            $previous[$name] = [string]$entry.Value
        }
    }
    try {
        foreach ($name in $previous.Keys) {
            Remove-Item -LiteralPath ("Env:" + $name)
        }
        # Even a successful status query can run a checkout-local monitor command.
        [Environment]::SetEnvironmentVariable('GIT_CONFIG_COUNT', '1')
        [Environment]::SetEnvironmentVariable('GIT_CONFIG_KEY_0', 'core.fsmonitor')
        [Environment]::SetEnvironmentVariable('GIT_CONFIG_VALUE_0', 'false')
        # Read the pinned Git objects, not a repository-local replacement ref.
        [Environment]::SetEnvironmentVariable('GIT_NO_REPLACE_OBJECTS', '1')
        & $Action
    } finally {
        foreach ($entry in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
            $name = [string]$entry.Key
            if ($name.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase)) {
                Remove-Item -LiteralPath ("Env:" + $name)
            }
        }
        foreach ($entry in $previous.GetEnumerator()) {
            Restore-BrowserCoreEnvironmentVariable $entry.Key $entry.Value
        }
    }
}
