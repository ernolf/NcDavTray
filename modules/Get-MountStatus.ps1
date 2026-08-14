# The one place that decides what state a mount is in: a drive test alone cannot
# say why a drive has gone away, and every caller needs the same answer.
#
# The order is the order in which the questions stop mattering: a mount that is
# switched off has nowhere to be, a mount without a usable letter has nowhere to
# go, and a server that does not answer explains every drive on it. Connected
# short-circuits the last question for callers that have just established the
# mount and would otherwise pay for the drive test a second time.
#
# Returns one of: disabled, invalid_drive, offline, maintenance, online, failed.
function Get-MountStatus {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][psobject]$Spec,
		[bool]$Enabled = $true,
		[object]$Connected = $null,
		[switch]$SkipServerCheck
	)
	if (-not $Enabled) { return 'disabled' }
	if (-not (Test-ValidDrive $Spec.Drive)) { return 'invalid_drive' }
	if (-not $SkipServerCheck) {
		$server = Get-NcServerStatusCached $Spec.Server
		if (-not $server.Reachable) { return 'offline' }
		if ($server.Maintenance) { return 'maintenance' }
	}
	$live = if ($null -ne $Connected) { [bool]$Connected } else { [bool](Test-DriveAccessible $Spec) }
	if ($live) { return 'online' }
	return 'failed'
}