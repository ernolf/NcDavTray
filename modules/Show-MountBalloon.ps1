# The same three lines NcDavTray puts up for its drive, for a mount of the
# manager. One product, one balloon: from the tray a drive of the manager is no
# different from a drive of NcDavTray, and the user should not have to know which
# of the two icons he is clicking on.
function Show-MountBalloon {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Id )
	$entry = Get-MountEntry $Id
	if (-not $entry) { return }
	# The share stands where NcDavTray shows the subfolder: it is what the drive
	# leads to. Its token is not part of it -- see Get-MountDisplayName.
	$sub = Get-MountDisplayName $entry
	if (-not [string]::IsNullOrWhiteSpace($entry.SubPath)) { $sub = '{0}/{1}' -f $sub, ([string]$entry.SubPath).Trim('/') }
	# The state comes from the last poll, not from the drive: reading a WebDAV drive
	# takes as long as the server needs, and this runs on the UI thread.
	$rec = $null
	if ($script:Trays.ContainsKey($Id)) { $rec = $script:Trays[$Id] }
	$status = if ($rec) { [string]$rec.Status } elseif (-not $entry.Enabled) { 'disabled' } else { 'failed' }
	$vars = @{ server = $entry.Server; drive = $entry.Drive; sub = $sub; status = (Get-MountStatusText $status) }
	Show-CustomBalloon -Title $AppName -Text (T 'tray.balloon' $vars) -TimeoutMs 6600
}