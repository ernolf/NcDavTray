# Fills the list with every configured mount. This window is the one place where
# the whole configuration is visible, and an entry left out of it is an entry the
# user cannot see at all.
# The status comes from the tray record, which is what the last poll worked out.
# Asking the drives again here would be a status request per server and a read per
# drive on the UI thread, for an answer that is one poll old at most -- and the
# poll refreshes this list itself, so it is never older than that. A mount that
# has no record yet is asked for directly: it was added a moment ago and has not
# been through a poll.
function Update-ShareListView {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.ListView]$ListView )
	$selected = ''
	if ($ListView.SelectedItems.Count -gt 0) { $selected = [string]$ListView.SelectedItems[0].Tag }
	$images = $ListView.SmallImageList
	$ListView.BeginUpdate()
	try {
		$ListView.Items.Clear()
		if ($images) { $images.Images.Clear() }
		foreach ($entry in @($State.Mounts)) {
			if (-not $entry) { continue }
			$rec = if ($script:Trays.ContainsKey($entry.Id)) { $script:Trays[$entry.Id] } else { $null }
			$status = if ($rec) { [string]$rec.Status } else { Get-MountStatus -Spec (New-MountSpecFromEntry $entry) -Enabled ([bool]$entry.Enabled) }
			$item = New-Object System.Windows.Forms.ListViewItem((Get-MountEntryLabel $entry))
			[void]$item.SubItems.Add([string]$entry.Server)
			[void]$item.SubItems.Add([string]$entry.Drive)
			[void]$item.SubItems.Add((Get-MountStatusText $status))
			$item.Tag = $entry.Id
			# The image list holds a copy, so the icon has done its work once it is in
			if ($images) {
				$icon = New-MountStatusIcon -Entry $entry -Status $status
				$images.Images.Add([string]$entry.Id, $icon)
				try { $icon.Dispose() } catch {}
				$item.ImageKey = [string]$entry.Id
			}
			[void]$ListView.Items.Add($item)
			if ($entry.Id -eq $selected) { $item.Selected = $true }
		}
	} finally { $ListView.EndUpdate() }
	# The longest name in the list is another one after every add, edit and remove.
	Update-ListViewColumns $ListView
}