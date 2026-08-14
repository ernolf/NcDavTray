function Get-CacheWatcherEntries {
	# Get current alive entries (may be empty if the list was deleted)
	$alive = Get-AliveInstanceEntries
	# Ensure that THIS process is registered as Ui in the instance list
	$hasOwnUi = $false
	if ($alive -and $alive.Count -gt 0) { foreach ($e in $alive) { [int]$pidValue = 0; try { $pidValue = [int]$e.Pid } catch { $pidValue = 0 }; if ($pidValue -eq $PID -and [string]$e.Role -eq 'Ui') { $hasOwnUi = $true; break } } }
	if (-not $hasOwnUi) {
		Write-Verbose "[CacheGlue] Get-CacheWatcherEntries: ensuring Ui registration for this process"
		try { Register-Instance -Role 'Ui' -Tag 'main' } catch {} # This recreates instances.json if the watcher deleted it, and adds our own Ui entry
		$alive = Get-AliveInstanceEntries
		if (-not $alive -or $alive.Count -eq 0) { Write-Verbose "[CacheGlue] Get-CacheWatcherEntries: still no alive entries after re-registering Ui"; return @() }
	}
	# Collect watcher entries from the refreshed alive set
	$watchers = @()
	foreach ($e in $alive) { if ([string]$e.Role -eq 'Watcher') { $watchers += $e } }
	Write-Verbose ("[CacheGlue] Get-CacheWatcherEntries: returning {0} watcher entries" -f $watchers.Count)
	return $watchers
}
