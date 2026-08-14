function Start-CacheWatcher([int]$IntervalSeconds = 3) {
	Write-Verbose ("[CacheGlue] Start-CacheWatcher: requested (IntervalSeconds={0})" -f $IntervalSeconds)
	if ($IntervalSeconds -le 0) { $IntervalSeconds = 3 }
	if (Ensure-CacheAgentRunning -IntervalSeconds $IntervalSeconds) { Write-Verbose ("[CacheGlue] Start-CacheWatcher: Ensure-CacheAgentRunning returned true"); return $true }
	Write-Verbose "[CacheGlue] Start-CacheWatcher: Ensure-CacheAgentRunning returned false"
	return $false
}
