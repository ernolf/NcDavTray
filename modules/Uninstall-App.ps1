# Uninstalling takes the installation folder and the registry key with it. What is
# offered beforehand are the two ways to get the configuration back afterwards.
function Uninstall-App {
	[CmdletBinding()] param()
	if ($PortableMode) { return }
	if (@($State.Mounts).Count -gt 0) {
		$ans1 = Ask-YesNoCancelQuestT 'prompt.export2json_before_uninstall' @{ app = $AppName }
		if ($ans1 -eq [System.Windows.Forms.DialogResult]::Cancel) { return }
		if ($ans1 -eq [System.Windows.Forms.DialogResult]::Yes) { try { Export-AppConfig -SkipConfirm } catch {} }
		$ans2 = Ask-YesNoCancelQuestT 'prompt.export2portable_before_uninstall' @{ appshort = $AppNameShort; app = $AppName }
		if ($ans2 -eq [System.Windows.Forms.DialogResult]::Cancel) { return }
		if ($ans2 -eq [System.Windows.Forms.DialogResult]::Yes) { try { Export-AppToPortable -SkipConfirm } catch {} }
	}
	# The drives come off before the folder they run from is taken away.
	$script:Quitting = $true
	try { if ($script:timer) { $script:timer.Stop(); $script:timer.Dispose() } } catch {}
	try { Unmap-AllMounts } catch {}
	try { foreach ($id in @($script:Trays.Keys)) { Remove-MountTray $id } } catch {}
	try { if ($script:mainMutex) { $script:mainMutex.ReleaseMutex() | Out-Null; $script:mainMutex.Dispose() } } catch {}
	try { if ($script:TrayManager -and $script:TrayManager.Notify) { $script:TrayManager.Notify.Visible = $false; $script:TrayManager.Notify.Dispose() } } catch {}
	try { [System.Windows.Forms.Application]::DoEvents() } catch {}
	Start-Sleep -Milliseconds 120
	try { Set-StartupRunKey $false $AppName $InstallBin } catch {}
	try { Ensure-Shortcut 'StartMenu' $false $AppName $InstallBin } catch {}
	try { Ensure-Shortcut 'Desktop' $false $AppName $InstallBin } catch {}
	# The whole key. The list, the account passwords and the record of which
	# migrations have run all sit under it, and none of them outlives the program
	# that wrote them.
	try { Remove-Item -LiteralPath (Get-RegBase) -Recurse -Force -ErrorAction SilentlyContinue } catch {}
	# A folder cannot delete itself while the script inside it is running, so a
	# small batch outlives this process and does it a moment later.
	try {
		if (Test-Path $InstallDir) {
			$bat = Join-Path $env:TEMP ("{0}-uninstall-{1}.cmd" -f $AppName, ([guid]::NewGuid()))
			$batContent = @(
				'@echo off',
				'setlocal',
				'ping -n 2 127.0.0.1 >nul',
				'rd /S /Q "%TARGETDIR%" >nul 2>nul',
				'endlocal'
			) -join "`r`n"
			$batContent = $batContent -replace '%TARGETDIR%', $InstallDir
			Set-Content -Path $bat -Value $batContent -Encoding ASCII
			Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList "/c `"$bat`"" -WindowStyle Hidden | Out-Null
		}
	} catch {}
	[System.Windows.Forms.Application]::Exit()
	exit
}