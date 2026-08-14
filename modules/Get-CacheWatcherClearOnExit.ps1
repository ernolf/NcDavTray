function Get-CacheWatcherClearOnExit {
	$entries = Read-InstanceEntries
	if (-not $entries -or $entries.Count -eq 0) { return $true }
	foreach ($e in $entries) {
		if ([string]$e.Role -eq 'Watcher') { if ($e.PSObject.Properties.Name -contains 'ClearOnExit') { try { return [bool]$e.ClearOnExit } catch { return $true } }; return $true } # Watcher without flag -> Default = true
	}
	return $true # No watcher entered -> Default = true
}
