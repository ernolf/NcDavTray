# Fills the picker and preselects a letter: the one the mount already holds where
# it is still to be had, otherwise a free one. Share mounts take theirs from the
# back of the alphabet -- that is the end users reach for, and the low letters
# belong to hardware. Called again whenever the account behind the box changes.
function Update-DriveLetterPicker {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.ComboBox]$ComboBox, [string]$Current = '', [AllowEmptyCollection()][string[]]$Reserved = @(), [ValidateSet('Lowest', 'Highest')][string]$Prefer = 'Lowest' )
	if (-not ($ComboBox.Tag -is [hashtable])) { Initialize-DriveLetterPicker -ComboBox $ComboBox }
	$tag = $ComboBox.Tag
	$tag.Current = if (Test-ValidDrive $Current) { ([string]$Current).ToUpperInvariant() } else { '' }
	# Letters other configured mounts are spoken for, normalized to "X:"
	$tag.Reserved = @(foreach ($r in @($Reserved)) { if (-not [string]::IsNullOrWhiteSpace($r)) { '{0}:' -f ([string]$r).Substring(0, 1).ToUpperInvariant() } })
	$used = @(Get-PSDrive -PSProvider FileSystem | Select-Object -Expand Name | ForEach-Object { '{0}:' -f $_ })
	# Rebuilding walks through the selection, and that is not a user's choice
	$script:DriveSelBusy = $true
	try {
		$ComboBox.Items.Clear()
		$tag.Statuses.Clear()
		foreach ($d in (68..90 | ForEach-Object { '{0}:' -f ([char]$_) })) {
			if ($d -eq $tag.Current) { $tag.Statuses[$d] = 'current' } elseif (($used -contains $d) -or ($tag.Reserved -contains $d)) { $tag.Statuses[$d] = 'used' } else { $tag.Statuses[$d] = 'free' }
			[void]$ComboBox.Items.Add($d)
		}
		if ($tag.Current -and ($tag.Statuses[$tag.Current] -in @('free', 'current'))) { $ComboBox.SelectedItem = $tag.Current }
		else {
			$freeItems = @($ComboBox.Items | Where-Object { $tag.Statuses[[string]$_] -eq 'free' })
			if ($Prefer -eq 'Highest') { [array]::Reverse($freeItems) }
			if ($freeItems.Count -gt 0) { $ComboBox.SelectedItem = [string]$freeItems[0] } else { $ComboBox.SelectedIndex = -1 }
		}
	} finally { $script:DriveSelBusy = $false }
	$tag.Prev = if ($ComboBox.SelectedItem) { [string]$ComboBox.SelectedItem } else { $null }
}