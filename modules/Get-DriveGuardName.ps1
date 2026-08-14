# Name of the system-wide guard on a drive letter, or $null for an invalid drive.
# Global\ so instances across sessions and desktops collide over a letter, and
# the literal product name so the guard survives a rename of $AppName.
function Get-DriveGuardName {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Drive )
	$d = $Drive.Trim().ToUpperInvariant()
	if (-not ($d -match '^[A-Z]:$')) { return $null }
	return 'Global\NcDavTray_drv_{0}' -f $d[0]
}
