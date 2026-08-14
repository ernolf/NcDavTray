function Set-CacheWatcherClearOnExit([bool]$value) {
	$entries = Read-InstanceEntries
	if (-not $entries -or $entries.Count -eq 0) { return }
	$changed = $false
	foreach ($e in $entries) {
		if ([string]$e.Role -eq 'Watcher') {
			try {
				if ($e.PSObject.Properties.Name -contains 'ClearOnExit') { $e.ClearOnExit = $value } else { $e | Add-Member -NotePropertyName 'ClearOnExit' -NotePropertyValue $value -Force }
				$changed = $true
			} catch {}
		}
	}
	if ($changed) { Write-InstanceEntries $entries }
}
