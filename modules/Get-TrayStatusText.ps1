# The tooltip the notification area shows for one mount: what the mount is
# called, the drive it sits on, and the same state word the balloon prints. Both
# programs come through here, so a share of the manager reads exactly like the
# drive of NcDavTray -- from the tray the two are the same thing.
function Get-TrayStatusText {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Name,
		[Parameter(Mandatory)][string]$Status,
		[AllowEmptyString()][string]$Drive = '',
		[int]$Rc = 0
	)
	$key = switch ($Status) {
		'online' { 'tray.status_online' }
		'offline' { 'tray.status_offline' }
		'maintenance' { 'tray.status_maintenance' }
		'invalid_drive' { 'tray.status_invalid_drive' }
		'pending' { 'tray.status_pending' }
		'blocked' { 'tray.status_blocked' }
		# The error code is the whole answer to why a drive did not come up, and this
		# is the only place the user ever gets to see it.
		'failed' { if ($Rc -ne 0) { 'tray.status_mapping_failed_rc' } else { 'tray.status_mapping_failed' } }
		# Whatever is left is the state the user asked for with Disconnect
		default { 'tray.status_disconnected' }
	}
	$vars = @{ name = $Name; drive = $Drive; rc = $Rc }
	$text = [string](T $key $vars)
	# Windows takes 63 characters of tooltip and drops the rest without asking. The
	# name is what gives way, not the tail: the state is the point of the tooltip,
	# and a name long enough to matter is one the user chose himself.
	if ($text.Length -gt 63) {
		$over = $text.Length - 63
		$short = if ($Name.Length -gt ($over + 1)) { $Name.Substring(0, $Name.Length - $over - 1) + [char]0x2026 } else { [string][char]0x2026 }
		$vars.name = $short
		$text = [string](T $key $vars)
		if ($text.Length -gt 63) { $text = $text.Substring(0, 63) }
	}
	return $text
}