# A copy that runs from anywhere: the script, its language packs, the mount list,
# the passwords and the launchers. The passwords cannot travel as they are -- DPAPI
# binds them to this user on this machine -- so they go in a file of their own,
# behind a passphrase asked for during the export. See Get-PortableSecretPayload.
# A portable copy has nothing to hand out that it is not already made of, so the
# window does not offer this and only the installer bootstrap asks for it there.
function Export-AppToPortable {
	[CmdletBinding()] param([switch]$SkipConfirm, [switch]$Force)
	if ($PortableMode -and -not $Force) { return }
	if (-not $SkipConfirm) { $ans = Ask-YesNoQuestT 'prompt.export2portable' @{ appshort = $AppNameShort; app = $AppName }; if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return } }
	$oldEAP = $ErrorActionPreference
	$ErrorActionPreference = 'Stop'
	try {
		$scriptPath = Get-ThisScriptPath
		if ([string]::IsNullOrWhiteSpace($scriptPath) -or -not (Test-Path -LiteralPath $scriptPath)) { throw ('Cannot resolve script path of {0}' -f $AppNameShort) }
		$scriptName = [System.IO.Path]::GetFileName($scriptPath); $hereAbs = [System.IO.Path]::GetDirectoryName($scriptPath)
		$dlg = New-Object System.Windows.Forms.FolderBrowserDialog
		# The installer starts in the folder it was unpacked into, which is the one the
		# user meant; an export from the window starts on the desktop.
		$dlg.Description = (T 'hint.select_portable_folder')
		$dlg.SelectedPath = if ($script:FromInstaller) { $hereAbs } else { [Environment]::GetFolderPath('Desktop') }
		if ($dlg.ShowDialog() -ne 'OK') { return }
		$chosen = [System.IO.Path]::GetFullPath($dlg.SelectedPath)
		# The folder the script itself sits in gets the launchers and nothing else:
		# copying a package onto itself is how a portable copy loses its own list.
		if ($chosen -ieq $hereAbs) { Write-PortableLaunchers -Destination $hereAbs -ScriptName $scriptName -SpdxFrom $scriptPath; $msg = T 'message.portable_launchers_inplace' @{ path = $hereAbs }; Show-InfoT $msg; return }
		# An existing package is updated where it stands, either the chosen folder
		# itself or the one this export would have created inside it.
		$updateInPlace = $false
		if (Test-IsPortableFolder -Path $chosen) { $dstRoot = $chosen; $updateInPlace = $true }
		else {
			$dstRoot = Join-Path $chosen ("{0}Portable" -f $AppName)
			if (Test-IsPortableFolder -Path $dstRoot) { $updateInPlace = $true }
			elseif (Test-Path -LiteralPath $dstRoot) {
				$count = (Get-ChildItem -LiteralPath $dstRoot -Force -ErrorAction SilentlyContinue | Measure-Object).Count
				if ($count -gt 0) {
					$ans2 = Ask-YesNoQuestT 'prompt.folder_is_not_empty_overwrite' @{ dir = $dstRoot }
					if ($ans2 -eq [System.Windows.Forms.DialogResult]::Yes) { try { Remove-Item -LiteralPath $dstRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
					else { $dstRoot = Join-Path $chosen ("{0}Portable_{1}" -f $AppName, (Get-Date -Format 'yyyyMMdd_HHmmss')) }
				}
			}
		}
		# Asked before anything is created, so a declined passphrase leaves no half
		# written package behind. An update keeps the file the package already has,
		# along with the list that file belongs to.
		# The installer writes launchers next to a package it did not build: there is no
		# list and no password of its own to put in one, and the ones already lying there
		# belong to whoever put them there.
		$bare = ($script:FromInstaller -eq $true)
		$secret = $null
		if (-not $bare -and -not $updateInPlace) { $secret = Get-PortableSecretPayload; if ($null -eq $secret) { return } }
		if (-not (Test-Path -LiteralPath $dstRoot)) { New-Item -ItemType Directory -Path $dstRoot -Force | Out-Null }
		$dstPs1 = Join-Path $dstRoot $scriptName
		Copy-Item -LiteralPath $scriptPath -Destination $dstPs1 -Force
		# Language packs are merged, never pruned: a pack installed into the target
		# by hand is not ours to remove.
		$srcI18n = Join-Path $hereAbs 'i18n'; $dstI18n = Join-Path $dstRoot 'i18n'
		if (-not (Test-Path -LiteralPath $dstI18n)) { New-Item -ItemType Directory -Path $dstI18n -Force | Out-Null }
		if (Test-Path -LiteralPath $srcI18n) { try { Copy-Item -Path (Join-Path $srcI18n '*') -Destination $dstI18n -Recurse -Force -ErrorAction SilentlyContinue } catch {} }
		# An update keeps the list the package already carries -- it is the one the
		# user built there, and overwriting it is what an update must not do.
		if (-not $bare -and -not $updateInPlace) {
			$State | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $dstRoot ("{0}_config.json" -f $AppNameShort)) -Encoding UTF8
			if ($secret.Json) { Protect-PortableSecret -Plain $secret.Json -Passphrase $secret.Passphrase -Path (Join-Path $dstRoot ("{0}_secret.dat" -f $AppNameShort)) }
		}
		Write-PortableLaunchers -Destination $dstRoot -ScriptName $scriptName -SpdxFrom $dstPs1
		$msgKey = if ($updateInPlace) { 'message.portable_package_updated' } else { 'message.portable_package_exported' }
		$msg = T $msgKey @{ path = [string]$dstRoot }; Show-InfoT $msg
	} catch { Show-ErrorT 'message.export_failed' @{ err = $_.Exception.Message } }
	finally { $ErrorActionPreference = $oldEAP }
}