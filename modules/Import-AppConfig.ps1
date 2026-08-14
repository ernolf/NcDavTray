# Reads back what Export-AppConfig wrote. The list replaces the one in force
# rather than being merged into it: a merge would have to decide what a drive
# letter claimed twice means, and there is no answer to that which is right more
# often than it is wrong. The mounts go down first, because they are the only
# ones that still know which letters they hold.
function Import-AppConfig {
	[CmdletBinding()] param()
	try {
		$dlg = New-Object System.Windows.Forms.OpenFileDialog
		$dlg.Title = (T 'title.import_config'); $dlg.Filter = 'JSON (*.json)|*.json'; $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
		if ($dlg.ShowDialog() -ne 'OK') { return }
		$json = Get-Content -Raw -Path $dlg.FileName -Encoding UTF8 | ConvertFrom-Json
		if (-not $json) { throw (T 'message.config_unreadable' @{ path = $dlg.FileName }) }
		$have = $json.PSObject.Properties.Name
		# Two shapes are readable: the list this version writes, and the single flat
		# account a backup from before 2.0.0 holds -- that one has no Mounts, and its
		# Server sits beside the settings instead of inside an entry. Which it is has
		# to be settled before the running mounts come down, so a file that is neither
		# leaves the installation as it was.
		$hasList = $have -contains 'Mounts'
		$hasFlat = (-not $hasList) -and ($have -contains 'Server')
		if (-not $hasList -and -not $hasFlat) { throw (T 'message.config_unreadable' @{ path = $dlg.FileName }) }
		try { Unmap-AllMounts } catch {}
		if ($have -contains 'IntervalS') { $State.IntervalS = [Math]::Min(600, [Math]::Max(5, [int]$json.IntervalS)) }
		if ($have -contains 'LangPref') { $State.LangPref = [string]$json.LangPref }
		if ($hasList) {
			$list = @()
			foreach ($m in @($json.Mounts)) { if ($m) { $list += (ConvertTo-MountEntry $m) } }
			$State.Mounts = $list
		} else {
			# One account is all the old format could hold, so it becomes the whole list.
			$entry = Convert-FlatAccountToMountEntry $json
			if (-not $entry) { throw (T 'message.config_unreadable' @{ path = $dlg.FileName }) }
			$State.Mounts = @($entry)
			# The old export called the blob DPAPI. It is the same protection this
			# version stores, bound to the same user on the same machine, so it is taken
			# over as it stands -- and it belongs to the pair, not to the mount.
			if ((-not $PortableMode) -and ($have -contains 'DPAPI')) { Set-AccountSecret -Server $entry.Server -User $entry.User -EncPass ([string]$json.DPAPI) }
		}
		# A portable copy has nowhere to put a DPAPI blob and could not read one it
		# was handed: it asks for the passwords again, as it always does.
		if ((-not $PortableMode) -and ($have -contains 'Accounts')) {
			foreach ($a in @($json.Accounts)) {
				if (-not $a) { continue }
				$parts = ([string]$a.Key -split '\|', 2)
				if ($parts.Count -ne 2) { continue }
				Set-AccountSecret -Server $parts[0] -User $parts[1] -EncPass ([string]$a.DPAPI)
			}
		}
		Save-Config
		Initialize-I18n $State.LangPref
		try { if ($script:timer) { $script:timer.Interval = ([Math]::Max(5, [int]$State.IntervalS) * 1000) } } catch {}
		if ($script:NumInterval -and -not $script:NumInterval.IsDisposed) { $script:NumInterval.Value = [int]$State.IntervalS }
		if ($script:RefreshLangList -is [scriptblock]) { & $script:RefreshLangList }
		if ($script:ApplyLanguageNow -is [scriptblock]) { & $script:ApplyLanguageNow }
		if ($script:ShareListView -and -not $script:ShareListView.IsDisposed) { Update-ShareListView $script:ShareListView }
		Connect-AllMounts
		Show-InfoT 'message.config_imported' @{ path = $dlg.FileName }
	} catch { Show-ErrorT 'message.import_failed' @{ err = $_.Exception.Message } }
}