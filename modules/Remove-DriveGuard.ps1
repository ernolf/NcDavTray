# Drops the guard on one drive letter, or on all of them without -Drive.
function Remove-DriveGuard {
	[CmdletBinding()] param( [string]$Drive )
	# Snapshot the keys: the loop removes entries from the table.
	$names = if ($Drive) { @(Get-DriveGuardName $Drive) } else { @($script:DriveGuards.Keys) }
	foreach ($name in $names) {
		if (-not $name -or -not $script:DriveGuards.ContainsKey($name)) { continue }
		Release-MutexSafe $script:DriveGuards[$name]
		$script:DriveGuards.Remove($name)
	}
}
