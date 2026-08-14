function Ensure-CacheAgentRunning([int]$IntervalSeconds = 3) {
	# If at least one watcher is registered in pids.json, we are done.
	try {
		$watchersRaw = Get-CacheWatcherEntries
		$watchers = @()
		if ($watchersRaw) { $watchers = @($watchersRaw) } # normalize
		if ($watchers.Count -gt 0) { Write-Verbose ("[CacheGlue] Ensure-CacheAgentRunning: watcher already present (Count={0})" -f $watchers.Count); return $true }
	} catch { Write-Verbose ("[CacheGlue] Ensure-CacheAgentRunning: error while checking watchers: {0}" -f $_.Exception.Message) }
	Write-Verbose ("[CacheGlue] Ensure-CacheAgentRunning: no watcher, starting elevated")
	return (Start-CacheAgentElevated -IntervalSeconds $IntervalSeconds)
}
