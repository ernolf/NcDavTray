# One /status.php request per host and poll instead of one per mount. A manager
# with five mounts on the same server would otherwise pay that round trip five
# times per tick, on the UI thread, for an answer that cannot have changed in
# between. The lifetime is short enough that a server coming back is noticed on
# the next poll and not the one after.
function Get-NcServerStatusCached {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [int]$MaxAgeS = 10 )
	if (-not $script:ServerStatusCache) { $script:ServerStatusCache = @{} }
	$key = ([string]$Server).ToLowerInvariant()
	$hit = $script:ServerStatusCache[$key]
	if ($hit -and (((Get-Date) - $hit.At).TotalSeconds -lt $MaxAgeS)) { return $hit.Status }
	$status = Get-NcServerStatus $Server
	$script:ServerStatusCache[$key] = @{ At = (Get-Date); Status = $status }
	return $status
}