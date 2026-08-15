# Everything that can be added, in one place. A new kind of mount -- an internal
# share, a WebDAV server that is not Nextcloud -- is one entry more here and
# nowhere else.
# The menu is built on every click rather than kept, so its labels are in the
# language that is current at that moment, the same way the tray menus do it.
# OnAdded is what the caller wants done afterwards; the menu itself knows nothing
# about the window it was opened from.
function Show-AddMenu {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.Control]$Under, [scriptblock]$OnAdded = $null )
	$done = $OnAdded
	$menu = New-Object System.Windows.Forms.ContextMenuStrip
	$miLink = $menu.Items.Add((T 'menu.add_share_link'))
	$miLink.Add_Click(({ Add-ShareFromLink; if ($done) { & $done } }).GetNewClosure())
	$miAccount = $menu.Items.Add((T 'menu.add_account'))
	$miAccount.Add_Click(({ Add-Account; if ($done) { & $done } }).GetNewClosure())
	# Under the button and flush with its left edge, so the menu reads as belonging
	# to it rather than appearing wherever the pointer happened to be.
	$menu.Show($Under, 0, $Under.Height)
}
