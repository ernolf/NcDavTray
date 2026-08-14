# Fills the list with every configured mount. This window is the one place where
# the whole configuration is visible, and an entry left out of it is an entry the
# user cannot see at all.
# The status is worked out here and not taken from a remembered value, because
# between two polls a mount can have gone away without anyone telling us about it.
# The server side of that answer is cached per host, so a list of five mounts on
# one server still costs one status request.
function Update-ShareListView {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.ListView]$ListView )
	$selected = ''
	if ($ListView.SelectedItems.Count -gt 0) { $selected = [string]$ListView.SelectedItems[0].Tag }
	$ListView.BeginUpdate()
	try {
		$ListView.Items.Clear()
		foreach ($entry in @($State.Mounts)) {
			if (-not $entry) { continue }
			$status = Get-MountStatus -Spec (New-MountSpecFromEntry $entry) -Enabled ([bool]$entry.Enabled)
			$item = New-Object System.Windows.Forms.ListViewItem((Get-MountEntryLabel $entry))
			[void]$item.SubItems.Add([string]$entry.Server)
			[void]$item.SubItems.Add([string]$entry.Drive)
			[void]$item.SubItems.Add((Get-MountStatusText $status))
			$item.Tag = $entry.Id
			[void]$ListView.Items.Add($item)
			if ($entry.Id -eq $selected) { $item.Selected = $true }
		}
	} finally { $ListView.EndUpdate() }
	# The longest name in the list is another one after every add, edit and remove.
	Update-ListViewColumns $ListView
}