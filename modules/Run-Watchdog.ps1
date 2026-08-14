# The guard process. It holds no drive of its own: it waits for the mutex of the
# program that started it to disappear and then cleans up what that program left
# mapped. That is the only path by which a program that was killed still gets its
# drives back off their letters -- an exit handler never runs in that case.
#
# What "clean up" means differs between the two deliverables (one drive against a
# list of them), and so does the question whether the program's storage is still
# there, so both come in as scriptblocks from the caller.
function Run-Watchdog {
	[CmdletBinding()] param(
		[Parameter(Mandatory)][scriptblock]$OnOwnerGone,
		[scriptblock]$OwnerBroken = $null
	)
	$created = $false
	$wdKey = if ($OwnerPid -gt 0) { "Local\{0}Watchdog-{1}" -f $AppName, $OwnerPid } else { $WDMutex }
	try { $wdMutex = New-Object System.Threading.Mutex($true, $wdKey, [ref]$created); if (-not $created) { return } } catch { return }
	while ($true) {
		$mainAlive = $false
		try { if (-not [string]::IsNullOrWhiteSpace($MainMutexName) -and ($m = [System.Threading.Mutex]::OpenExisting($MainMutexName))) { $mainAlive = $true; $m.Dispose() } } catch { $mainAlive = $false }
		if (-not $mainAlive) { try { Load-Config; & $OnOwnerGone } catch {}; break }
		if ($OwnerBroken) {
			$broken = $false
			try { $broken = [bool](& $OwnerBroken) } catch { $broken = $true }
			if ($broken) { try { Load-Config; & $OnOwnerGone } catch {}; break }
		}
		Start-Sleep -Seconds 2
	}
	try { $wdMutex.ReleaseMutex() | Out-Null } catch {}
	try { $wdMutex.Dispose() } catch {}
}
