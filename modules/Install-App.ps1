# Moving a portable copy into the install folder. Passwords are only in memory
# here, so they go where an installed copy looks for them -- see Set-AccountSecret
# -- and everything else is written the way Save-Config writes it.
# The installer bootstrap comes through here as well, and two things are not its
# business: there is no session worth importing, and starting the new copy is the
# bootstrap's own last step -- see Start-InstalledInstance.
function Install-App {
	[CmdletBinding()] param( [switch]$FromInstaller )
	if (-not $PortableMode) { Show-InfoT 'message.already_installed_appdata'; return }
	try {
		if (-not (Test-Path -LiteralPath $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
		Copy-Item -LiteralPath $PSCommandPath -Destination $InstallBin -Force
		$srcI18n = Join-Path $HereDir 'i18n'; $dstI18n = Join-Path $InstallDir 'i18n'
		if (-not (Test-Path -LiteralPath $dstI18n)) { New-Item -ItemType Directory -Path $dstI18n -Force | Out-Null }
		if (Test-Path -LiteralPath $srcI18n) { try { Copy-Item -Path (Join-Path $srcI18n '*') -Destination $dstI18n -Recurse -Force } catch {} }
		Ensure-AppBrandIcons
		$iconDst = Join-Path $InstallDir ("{0}.ico" -f $AppNameShort)
		try { [System.IO.File]::WriteAllBytes($iconDst, (Get-EmbeddedIconBytes)) } catch {}
		# The settings of this copy, if they are wanted. The registry is where the
		# installed copy reads them, and the passwords of the running session are the
		# only ones there are: a portable copy keeps no file to unlock.
		$ans = if ($FromInstaller) { [System.Windows.Forms.DialogResult]::No } else { Ask-YesNoQuestT 'prompt.import_portable_settings_to_installed' }
		if ($ans -eq [System.Windows.Forms.DialogResult]::Yes) {
			$base = Get-RegBase
			if (-not (Test-Path -LiteralPath $base)) { New-Item -Path $base -Force | Out-Null }
			New-ItemProperty -LiteralPath $base -Name 'IntervalS' -Value ([int]$State.IntervalS) -PropertyType DWord -Force | Out-Null
			New-ItemProperty -LiteralPath $base -Name 'LangPref' -Value ([string]$State.LangPref) -PropertyType String -Force | Out-Null
			New-ItemProperty -LiteralPath $base -Name 'TrayIcons' -Value ([int][bool]$State.TrayIcons) -PropertyType DWord -Force | Out-Null
			Write-MountEntriesToRegistry -Entries @($State.Mounts)
			$accounts = Get-AccountsRegPath
			if (-not (Test-Path -LiteralPath $accounts)) { New-Item -Path $accounts -Force | Out-Null }
			foreach ($name in @($script:AccountSecretCache.Keys)) {
				$blob = [string]$script:AccountSecretCache[$name]
				if ([string]::IsNullOrEmpty($blob)) { continue }
				New-ItemProperty -LiteralPath $accounts -Name $name -Value $blob -PropertyType String -Force | Out-Null
			}
		}
		$launch = Get-LauncherFor $InstallBin
		New-ItemProperty -Path $RunKey -Name $AppName -Value ("`"{0}`" {1}" -f $launch[0], $launch[1]) -PropertyType String -Force | Out-Null
		$lnkIco = Join-Path $InstallDir ("{0}.ico" -f $AppNameShort)
		if (-not (Test-Path -LiteralPath $lnkIco)) { $lnkIco = $null }
		New-Shortcut -lnkPath (Get-StartMenuShortcutPath $AppName) -scriptPath $InstallBin -IconPath $lnkIco
		New-Shortcut -lnkPath (Get-DesktopShortcutPath $AppName) -scriptPath $InstallBin -IconPath $lnkIco
		try { Show-InfoT 'message.installed_to_appdata_success' } catch {}
		# The drives go down before the installed copy comes up: it maps the same
		# letters from the same list, and two copies reaching for one letter is a race
		# neither of them wins.
		try { if ($script:timer) { $script:timer.Stop(); $script:timer.Dispose() } } catch {}
		try { Unmap-AllMounts } catch {}
		try { foreach ($id in @($script:Trays.Keys)) { Remove-MountTray $id } } catch {}
		# The working directory goes with the installation, not with wherever the
		# portable copy was started from -- a process holds its own directory open, and
		# that folder is usually the one the user wants to delete right afterwards.
		if (-not $FromInstaller) {
			$exe, $args = Get-LauncherFor $InstallBin
			Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $InstallDir -WindowStyle Hidden | Out-Null
		}
		try { if ($script:mainMutex) { $script:mainMutex.ReleaseMutex() | Out-Null; $script:mainMutex.Dispose() } } catch {}
		try { if ($script:TrayManager -and $script:TrayManager.Notify) { $script:TrayManager.Notify.Visible = $false; $script:TrayManager.Notify.Dispose() } } catch {}
		[System.Windows.Forms.Application]::Exit()
	} catch { Show-ErrorT 'message.install_failed' @{ err = $_.Exception.Message } }
}