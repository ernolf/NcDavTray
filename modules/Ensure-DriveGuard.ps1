## Guard a drive letter (stores mutexes in $script:DriveGuards, one per letter)
# Reports whether the guard is held. An occupied letter is not fatal here: what a
# process does about it depends on whether the mount is its only one, so the
# decision belongs to the caller.
function Ensure-DriveGuard {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Drive )
	$key = Get-DriveGuardName $Drive
	if (-not $key) { return $false }	# ignore invalid
	if ($script:DriveGuards.ContainsKey($key)) { return $true }
	# Use a normal var + [ref], not New-Object PSReference
	$mutexVar = $null
	if (-not (Acquire-NamedMutex -Name $key -MutexOut ([ref]$mutexVar))) { return $false }
	$script:DriveGuards[$key] = $mutexVar
	return $true
}
