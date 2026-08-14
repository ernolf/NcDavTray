# What the manager has to say about itself: one line per configured mount,
# disabled ones included. The application icon is the one icon that is always
# there, so it is the only place that can answer "what is connected right now"
# whatever the mounts do with their own icons.
function Show-ManagerBalloon {
	[CmdletBinding()] param()
	$lines = @()
	foreach ($entry in @($State.Mounts)) {
		if (-not $entry) { continue }
		# The state comes from the last poll, not from the drive: reading a WebDAV
		# drive takes as long as the server needs, and this runs on the UI thread.
		$rec = $null
		if ($script:Trays.ContainsKey($entry.Id)) { $rec = $script:Trays[$entry.Id] }
		$status = if (-not $entry.Enabled) { 'disabled' } elseif ($rec) { [string]$rec.Status } else { 'failed' }
		$vars = @{ drive = $entry.Drive; share = (Get-MountDisplayName $entry); server = $entry.Server; status = (Get-MountStatusText $status) }
		$lines += [string](T 'tray.balloon_mount_line' $vars)
	}
	if ($lines.Count -eq 0) { $lines = @([string](T 'tray.balloon_no_shares')) }
	Show-CustomBalloon -Title $AppName -Text ($lines -join "`n") -TimeoutMs 6600
}