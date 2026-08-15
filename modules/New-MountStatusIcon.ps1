# Tray icon for one mount: the drive letter on a round badge for an account and on
# a rounded square for a share, the same shapes NcDavTray uses. The shape says what
# kind of mount it is, and that is what the menu behind it offers -- a clone of an
# account is an account, reaches the same folders as the original and is set up on
# the same page, so it has no business looking unlike it.
# A mount whose drive letter is unusable shows the warning glyph instead, because a
# letter that cannot be rendered is exactly the case the user has to look at.
function New-MountStatusIcon {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry, [Parameter(Mandatory)][string]$Status )
	$valid = (-not [string]::IsNullOrWhiteSpace($Entry.Drive)) -and ($Entry.Drive -match '^[A-Za-z]:$')
	$label = if ($valid) { $Entry.Drive.Substring(0, 2) } else { '!' }
	$color = if (-not $valid) { [System.Drawing.Color]::Goldenrod }
	elseif ($Status -eq 'online') { [System.Drawing.Color]::LimeGreen }
	elseif ($Status -in @('pending', 'blocked')) { [System.Drawing.Color]::Goldenrod }
	else { [System.Drawing.Color]::Tomato }
	# The legacy endpoint is where a share ends up precisely when the server asked
	# for a password, so it is what tells the two kinds of share apart on sight.
	$shape = if ($Entry.Kind -eq 'account') { 'circle' } else { 'rounded' }
	return (New-StatusIcon $label $color -Shape $shape -Locked:($Entry.Kind -eq 'share-legacy'))
}