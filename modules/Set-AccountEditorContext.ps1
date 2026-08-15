# What the account settings page edits, and what has to happen when it saves.
# The page asks nothing beyond these, so this is where an entry of the mount list
# is put in front of it.
function Set-AccountEditorContext {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	# A working copy, because the page writes into it while it is open and a cancelled
	# window must leave the list as it was. The one field the page needs on top of a
	# mount entry is fetched separately: the password blob belongs to the server/user
	# pair, not to the entry.
	$script:Edit = [pscustomobject]@{
		Id = $Entry.Id; Server = $Entry.Server; Kind = $Entry.Kind; User = $Entry.User; Token = $Entry.Token
		SubPath = $Entry.SubPath; Drive = $Entry.Drive; Label = $Entry.Label
		ExplicitPort = [bool]$Entry.ExplicitPort; Enabled = [bool]$Entry.Enabled
		EncPass = (Get-AccountSecret -Server $Entry.Server -User $Entry.User)
	}
	# The name as last persisted, for the remap decision below. The four values the
	# page hands to EditApplyChanges do not include it, and a renamed mount has to be
	# mapped again as well -- see Update-ShareById.
	$script:EditPrevLabel = [string]$Entry.Label
	$script:EditSave = {
		$e = New-MountEntry -Id $script:Edit.Id -Server $script:Edit.Server -Kind $script:Edit.Kind -User $script:Edit.User -Token $script:Edit.Token -SubPath $script:Edit.SubPath -Drive $script:Edit.Drive -Label ([string]$script:Edit.Label) -ExplicitPort:([bool]$script:Edit.ExplicitPort) -Enabled:([bool]$script:Edit.Enabled)
		$list = @(); $found = $false
		foreach ($x in @($State.Mounts)) { if ($x) { if ($x.Id -eq $e.Id) { $list += $e; $found = $true } else { $list += $x } } }
		# A new account is on this page before it is in the list -- see Add-Account.
		if (-not $found) { $list += $e }
		$State.Mounts = $list
		Save-Config
	}
	$script:EditPlainPassword = { Unprotect-MountSecret -Entry $script:Edit }
	$script:EditSetPassword = {
		param([string]$Plain)
		Set-AccountPassword -Server $script:Edit.Server -User $script:Edit.User -Plain $Plain
		$script:Edit.EncPass = (Get-AccountSecret -Server $script:Edit.Server -User $script:Edit.User)
	}
	$script:EditClearPassword = {
		Set-AccountPassword -Server $script:Edit.Server -User $script:Edit.User -Plain ''
		$script:Edit.EncPass = ''
	}
	# An installed copy stores a password by writing it; a portable one has to put the
	# whole file back afterwards, and can be refused the passphrase it needs for that.
	# That is the difference the page has to know about, and all of it.
	$script:EditSecretFile = $PortableMode
	$script:EditHasSecret = { -not [string]::IsNullOrEmpty($script:Edit.EncPass) }
	$script:EditWriteSecret = {
		param([string]$Plain)
		if ([string]::IsNullOrWhiteSpace($Plain)) { return $false }
		& $script:EditSetPassword $Plain
		# A refused passphrase leaves nothing stored: keeping the password in the table
		# alone would work until the program ends and then be gone without having said so.
		if (-not (Save-PortableSecretStore)) { & $script:EditClearPassword; return $false }
		return $true
	}
	$script:EditRemoveSecret = {
		if ((Ask-YesNoQuestT 'prompt.clear_stored_password') -ne [System.Windows.Forms.DialogResult]::Yes) { return $false }
		& $script:EditClearPassword
		[void](Save-PortableSecretStore)
		return $true
	}
	# Nothing left to unlock here: that happened once, before the first mount.
	$script:EditUnlockSecret = { return $true }
	# The tray belongs to the program around this window, and a language change has
	# to reach it as well -- see Update-TrayTips for what it does and does not touch.
	$script:EditApplyLanguage = { try { Update-TrayTips } catch {} }
	# After a save: what the new values mean for the running mount.
	$script:EditApplyChanges = {
		param([string]$OldServer, [string]$OldUser, [string]$OldSubPath, [string]$OldDrive)
		$now = Get-MountEntry $script:Edit.Id
		if (-not $now) { return }
		# An account that has just been added has never been mapped: there is no drive
		# to take down, and nothing to describe the mapping that was not there with.
		if (-not [string]::IsNullOrWhiteSpace($OldServer) -and -not [string]::IsNullOrWhiteSpace($OldDrive)) {
			$oldSpec = New-MountSpec -Server $OldServer -Kind $now.Kind -User $OldUser -Token $now.Token -SubPath $OldSubPath -Drive $OldDrive -Label $script:EditPrevLabel -ExplicitPort:([bool]$now.ExplicitPort)
			if (((Get-MountKey $oldSpec) -ne (Get-MountKey (New-MountSpecFromEntry $now))) -or ($script:EditPrevLabel -ne $now.Label)) {
				try { Unmap-DriveIfOurs -Spec $oldSpec -Force -RemoveProfile } catch {}
				try { Refresh-ExplorerDriveRemoval $oldSpec.Drive } catch {}
				try { Remove-MapMutex -Spec $oldSpec } catch {}
				try { Remove-DriveGuard -Drive $oldSpec.Drive } catch {}
				# Cancelling the connection is not the same as the letter being free again:
				# the redirector tears the session down in its own time, and mapping into a
				# letter it still holds answers ERROR_ALREADY_ASSIGNED.
				[void](Wait-DriveFullyUnmapped -Drive $oldSpec.Drive -TimeoutMs 3000)
			}
		}
		$script:EditPrevLabel = [string]$now.Label
		if ($now.Enabled) { Connect-MountById $now.Id } else { Update-Trays }
	}
}
