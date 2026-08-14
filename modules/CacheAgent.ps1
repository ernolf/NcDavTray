function CacheAgent([int]$OwnerPid,[int]$IntervalSeconds = 3) {
	$ErrorActionPreference = 'Stop'
	if ($IntervalSeconds -le 0) { $IntervalSeconds = 3 }
	$script:CacheAgentStopRequested = $false
	$script:CacheAgentExplicitStopRequested = $false
	Register-Instance -Role 'Watcher' -Tag 'cache'
	# Ensure watcher entry has a ClearOnExit flag (default true)
	try { $flag = Get-CacheWatcherClearOnExit; Set-CacheWatcherClearOnExit -value $flag } catch {}
	# WebDAV Redirector cache root for WebClient service
	function Get-CacheSnapshot {
		# Returns a hashtable with basic summary for the cache
		$root = Join-Path $env:WINDIR 'ServiceProfiles\LocalService\AppData\Local\Temp\TfsStore\Tfs_DAV'
		$snapshot = [ordered]@{ Root = $root; Exists = $false; TotalBytes = 0; FileCount = 0; NewestWriteTimeUtc = $null; OldestWriteTimeUtc = $null; Files = @() }
		if (-not $root -or -not (Test-Path -LiteralPath $root)) { return $snapshot }
		$snapshot.Exists = $true; $newest = $null; $oldest = $null; [int64]$totalBytes = 0; [int]$count = 0; $files = @()
		try {
			Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop | ForEach-Object {
				$count++
				$len = [int64]$_.Length
				$totalBytes += $len
				$wt = $_.LastWriteTimeUtc
				if (-not $newest -or $wt -gt $newest) { $newest = $wt }
				if (-not $oldest -or $wt -lt $oldest) { $oldest = $wt }
				$type = [System.IO.Path]::GetExtension($_.Name)
				if ([string]::IsNullOrEmpty($type)) { $type = 'file' } else { $type = $type.TrimStart('.').ToLowerInvariant() }
				$files += [pscustomobject]@{ Name = $_.Name; FullName = $_.FullName; Length = $len; LastWriteTimeUtc = $wt; Type = $type }
			}
		} catch { } # Partial failure is acceptable, we just return what we have
		$snapshot.TotalBytes = $totalBytes
		$snapshot.FileCount = $count
		$snapshot.Files = $files
		$snapshot.NewestWriteTimeUtc = if ($newest) { $newest.ToString('o') } else { $null }
		$snapshot.OldestWriteTimeUtc = if ($oldest) { $oldest.ToString('o') } else { $null }
		return $snapshot
	}
	function Write-CacheState([Parameter(Mandatory = $true)][hashtable]$Snapshot, [string]$LastAction = $null, [string]$LastError = $null) {
		$statePath = Get-CacheAgentStatePath
		$tmpPath = $statePath + '.tmp'
		$payload = [ordered]@{ TimestampUtc = (Get-Date).ToUniversalTime().ToString('o'); Snapshot = $Snapshot }
		if ($LastAction) { $payload.LastAction = $LastAction }
		if ($LastError) { $payload.LastError = $LastError }
		try { $json = $payload | ConvertTo-Json -Depth 6; $json | Set-Content -LiteralPath $tmpPath -Encoding UTF8; Move-Item -LiteralPath $tmpPath -Destination $statePath -Force } catch { } # If we cannot write state, there is not much else we can do
	}
	function Get-PendingCommand {
		# Reads and deletes command.json atomically. Returns a deserialized object or $null.
		$cmdPath = Get-CacheAgentCommandPath
		if (-not (Test-Path -LiteralPath $cmdPath)) { return $null }
		try {
			$raw = Get-Content -LiteralPath $cmdPath -Raw -ErrorAction Stop
			if (-not $raw) { Remove-Item -LiteralPath $cmdPath -Force -ErrorAction SilentlyContinue; return $null }
			$cmd = $raw | ConvertFrom-Json -ErrorAction Stop
			Remove-Item -LiteralPath $cmdPath -Force -ErrorAction SilentlyContinue
			return $cmd
		} catch { try { Remove-Item -LiteralPath $cmdPath -Force -ErrorAction SilentlyContinue } catch {}; return $null }
	}
	function Execute-CacheCommand([Parameter(Mandatory = $true)][object]$Command, [string]$Root) {
		$result = [ordered]@{ Action = $null; Ok = $false; DeletedCount = 0; DeletedBytes = 0; Error = $null }
		if (-not $Command) { $result.Error = 'Command is null'; return $result }
		$action = [string]$Command.Action
		if ([string]::IsNullOrWhiteSpace($action)) { $result.Error = 'Missing Action field'; return $result }
		$result.Action = $action
		if (-not $Root -or -not (Test-Path -LiteralPath $Root)) { $result.Error = 'Cache root not found'; return $result }
		$rootFull = $null
		try { $rootFull = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).ProviderPath.TrimEnd('\') } catch { $result.Error = 'Could not resolve cache root'; return $result }
		switch ($action.ToLowerInvariant()) {
			'deleteall' {
				try {
					$files = Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue
					foreach ($f in $files) { try { $len = [int64]$f.Length; Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $result.DeletedCount++; $result.DeletedBytes += $len } catch {} }
					$result.Ok = $true
				} catch { $result.Error = $_.Exception.Message }
			}
			'stop' { $script:CacheAgentStopRequested = $true; $script:CacheAgentExplicitStopRequested = $true; $result.Ok = $true } # Set global stop flag so outer loop can terminate cleanly
			default { $result.Error = "Unknown action '$action'" }
		}
		return $result
	}
	$ownerProcess = $null
	if ($OwnerPid -gt 0) { try { $ownerProcess = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue } catch { $ownerProcess = $null } }
	try {
		while ($true) {
			# Clean dead PIDs at every tick
			Get-AliveInstanceEntries | Out-Null
			if ($OwnerPid -gt 0) { # If owner process is gone, request a clean stop
				if ($ownerProcess -eq $null) { $ownerProcess = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue; if (-not $ownerProcess) { $script:CacheAgentStopRequested = $true } }
				else { try { $ownerProcess.Refresh(); if ($ownerProcess.HasExited) { $script:CacheAgentStopRequested = $true } } catch { $script:CacheAgentStopRequested = $true } }
			}
			$snapshot = Get-CacheSnapshot; $lastAction = $null; $lastError = $null; $cmd = Get-PendingCommand
			if ($cmd) { $res = Execute-CacheCommand -Command $cmd -Root $snapshot.Root; $lastAction = $res.Action; if (-not $res.Ok -and $res.Error) { $lastError = $res.Error }; if ($res.Ok) { $snapshot = Get-CacheSnapshot } }
			Write-CacheState -Snapshot $snapshot -LastAction $lastAction -LastError $lastError
			# Auto-stop if no UI instance is registered anymore
			if (-not (Test-AnyInstanceRole -Role 'Ui')) { $script:CacheAgentStopRequested = $true }
			if ($script:CacheAgentStopRequested) {
				$doClear = $false
				if (-not $script:CacheAgentExplicitStopRequested) { try { $doClear = Get-CacheWatcherClearOnExit } catch { $doClear = $true } }
				if ($doClear) {
					try {
						$snap = Get-CacheSnapshot
						if ($snap -and $snap.Root -and (Test-Path -LiteralPath $snap.Root)) {
							Get-ChildItem -LiteralPath $snap.Root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch {} }
						}
					} catch {}
				}
				# On stop, remove state.json so UIs will no longer see an active watcher
				try { $statePath = Get-CacheAgentStatePath; if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath -Force -ErrorAction SilentlyContinue } } catch {}
				# Leave the instance list, but only our own entry: it is shared now
				try { Unregister-Instance -Role 'Watcher' } catch {}
				break
			}
			Start-Sleep -Seconds $IntervalSeconds
		}
	} catch { try { $snap = Get-CacheSnapshot; Write-CacheState -Snapshot $snap -LastAction 'fatal' -LastError $_.Exception.Message } catch {} }
}
