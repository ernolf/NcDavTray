# The status vocabulary, in one place: share list, balloon and tray tooltip say
# the same word for the same state.
function Get-MountStatusText([string]$Status) {
	$key = switch ($Status) {
		'invalid_drive' { 'status.invalid_drive' }
		'offline' { 'status.offline' }
		'maintenance' { 'status.maintenance' }
		'online' { 'status.online' }
		'failed' { 'status.mapping_failed' }
		'pending' { 'status.connecting' }
		'blocked' { 'status.waiting_slot' }
		# Whatever is left is the state the user asked for with Disconnect
		default { 'status.disconnected' }
	}
	return [string](T $key)
}