# Establishes one mount and reports whether its drive letter is connected to the
# entry's target afterwards. Every reason to stop is local to this entry: nothing
# in here ends the process, because the other mounts are unaffected by it.
# LastError receives the WNetAddConnection2 return code when the connect was
# attempted, and is left untouched otherwise.
function Map-MountEntry {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry, [ref]$LastError )
	$spec = New-MountSpecFromEntry $Entry
	if (-not (Test-ValidDrive $spec.Drive)) { return $false }
	if ([string]::IsNullOrWhiteSpace($spec.Server) -or [string]::IsNullOrWhiteSpace((Get-MountIdentity $spec))) { return $false }
	# Claim the letter before anything touches it, then the mount itself.
	if (-not (Ensure-DriveGuard -Drive $spec.Drive)) { return $false }
	$mapOwned = Ensure-MapMutex $spec
	$occupied = (Get-PSDrive -PSProvider FileSystem | ForEach-Object { '{0}:' -f $_.Name }) -contains $spec.Drive
	if ($occupied) {
		if (Test-DriveMatchesDesired $spec) {
			# Already connected to this target: nothing to map, only branding to keep
			# up. Ensure-BrandingTick rather than Apply-WebDavBranding, because this
			# runs on every poll and only the former writes when something is missing.
			$ok = Test-DriveAccessible $spec
			if ($ok) { try { Ensure-BrandingTick $spec } catch {} }
			return $ok
		}
		# The letter carries a foreign mapping. Taking it over is only ours to do
		# if we hold the claim on this mount.
		if (-not $mapOwned) { return $false }
	}
	# $null means the password has not been asked for yet, so there is nothing to try
	$pass = (Get-MountRuntime $Entry.Id).Pass
	if ($null -eq $pass) { return $false }
	Unmap-DriveIfOurs -Spec $spec
	[int]$rc = 0
	$connected = New-WebDavMapSecure -drive $spec.Drive -unc (Build-Unc $spec) -user (Get-MountLogin $spec) -pass $pass -LastError ([ref]$rc)
	# ERROR_ALREADY_ASSIGNED says the letter is still taken, which after a mapping that
	# was just taken down means the redirector has not finished letting go of it. That
	# is a matter of waiting, not a failure to report -- the next poll would map it
	# anyway, and the user would have been told about a mount that came up.
	if ((-not $connected) -and ($rc -eq 85)) {
		Unmap-DriveIfOurs -Spec $spec -Force -RemoveProfile
		if (Wait-DriveFullyUnmapped -Drive $spec.Drive -TimeoutMs 3000) {
			$connected = New-WebDavMapSecure -drive $spec.Drive -unc (Build-Unc $spec) -user (Get-MountLogin $spec) -pass $pass -LastError ([ref]$rc)
		}
	}
	if ($PSBoundParameters.ContainsKey('LastError')) { $LastError.Value = $rc }
	if (-not $connected) { return $false }
	if (-not (Test-DriveAccessible $spec)) { return $false }
	try { Apply-WebDavBranding $spec } catch {}
	return $true
}
