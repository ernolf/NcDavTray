function Start-CacheAgentElevated([int]$IntervalSeconds = 3) {
	try {
		$scriptPath = Get-ThisScriptPath
		if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath)) { return $false }
		if ($IntervalSeconds -le 0) { $IntervalSeconds = 3 }
		# Clean up stale command/state files before starting a fresh agent
		try {
			$cmdPath = Get-CacheAgentCommandPath
			if (Test-Path -LiteralPath $cmdPath) { Remove-Item -LiteralPath $cmdPath -Force -ErrorAction SilentlyContinue }
			# also clear a very old state.json so we start clean
			$statePath = Get-CacheAgentStatePath
			if (Test-Path -LiteralPath $statePath) {
				$fi = Get-Item -LiteralPath $statePath -ErrorAction SilentlyContinue
				if ($fi) { $ageSeconds = ([DateTime]::UtcNow - $fi.LastWriteTimeUtc).TotalSeconds; if ($ageSeconds -gt 5) { Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue } }
			}
		} catch {}
		$psi = New-Object System.Diagnostics.ProcessStartInfo
		$psi.FileName = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
#		$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Action CacheAgent -OwnerPid $PID -IntervalSeconds $IntervalSeconds"
		$psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Action CacheAgent -IntervalSeconds $IntervalSeconds" # No `-OwnerPid $PID`
		$psi.Verb = 'runas'
		$psi.WindowStyle = 'Hidden'
		$psi.UseShellExecute = $true
		[System.Diagnostics.Process]::Start($psi) | Out-Null
		return $true
	} catch { return $false }
}
