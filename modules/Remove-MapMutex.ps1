# Drops the claim on one mount, or on all of them without -Spec. Call it where a
# mount leaves the configuration and at process exit, not on an ordinary unmap.
function Remove-MapMutex {
	[CmdletBinding()] param( [psobject]$Spec )
	# Snapshot the keys: the loop removes entries from the table.
	$names = if ($Spec) { @(Get-MapMutexName $Spec) } else { @($script:MapMutexes.Keys) }
	foreach ($name in $names) {
		if (-not $script:MapMutexes.ContainsKey($name)) { continue }
		$entry = $script:MapMutexes[$name]
		if ($entry.Owned) { try { $entry.Obj.ReleaseMutex() | Out-Null } catch {} }
		try { $entry.Obj.Dispose() } catch {}
		$script:MapMutexes.Remove($name)
	}
}
