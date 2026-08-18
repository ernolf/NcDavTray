# Hands the installation to the copy that was just downloaded and clears the way
# for it. A script cannot be written over while the process running it is still
# there, so the new copy does the writing and this one is what it writes over --
# the same division Installer.cmd has always used, not a second one beside it.
function Start-UpdateHandover {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$ScriptPath )
	$exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
	# Where this copy lives is what the new one has to write over, and it is not
	# derivable there: an install folder is, a portable folder is anywhere at all.
	$target = if ($IsInstalled) { $InstallDir } else { $HereDir }
	$fmt = '-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "{0}" -Action Update -Target "{1}" -OwnerPid {2}'
	try { Start-Process -FilePath $exe -ArgumentList ($fmt -f $ScriptPath, $target, $PID) -WorkingDirectory (Split-Path -Parent $ScriptPath) -WindowStyle Hidden | Out-Null }
	catch { return $false }
	# Started first, then torn down: the new copy spends its first moments loading
	# itself, which is the head start this needs to have the drives down before it
	# looks for them. What that head start does not cover, the watchdog does -- it
	# unmaps whatever is left the moment this process is gone.
	$script:Quitting = $true
	try { if ($script:timer) { $script:timer.Stop() } } catch {}
	try { Unmap-AllMounts } catch {}
	try { foreach ($id in @($script:Trays.Keys)) { Remove-MountTray $id } } catch {}
	[System.Windows.Forms.Application]::Exit()
	return $true
}
