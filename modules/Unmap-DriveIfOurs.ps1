# Call this everywhere the drive is torn down so label + icon are cleaned consistently
function Unmap-DriveIfOurs {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][psobject]$Spec,
		[switch]$RemoveProfile, [switch]$Force
	)
	$drive = $Spec.Drive
	if (-not (Test-ValidDrive $drive)) { return }
	if (-not $Force) { if (-not ((Test-MapMutexOwned $Spec) -or (Test-DriveMatchesDesired $Spec))) { return } }
	# Whether the letter carries anything at all. The teardown below runs either
	# way -- a connection the redirector still knows about does not have to show
	# up as a drive -- but telling the shell a drive has gone when none was there
	# costs a full Explorer and taskbar redraw, and a mount that fails is torn
	# down before every retry.
	$present = (Get-PSDrive -PSProvider FileSystem | ForEach-Object { '{0}:' -f $_.Name }) -contains $drive
	# disconnect letter ...
	$flags = if ($RemoveProfile) { [Nc.NetUse]::CONNECT_UPDATE_PROFILE } else { 0 }
	try { [void][Nc.NetUse]::WNetCancelConnection2($drive, $flags, $true) } catch {}
	# also by UNC ...
	try { $unc = if ($Spec.Server -and (Get-MountIdentity $Spec)) { Build-Unc $Spec } else { $null }; if ($unc) { [void][Nc.NetUse]::WNetCancelConnection2($unc, $flags, $true) } } catch {}
	try { Remove-PSDrive -Name $drive.Substring(0, 1) -Force -ErrorAction SilentlyContinue } catch {}
	try { if (Get-PSDrive -Name $drive.Substring(0, 1) -ErrorAction SilentlyContinue) { Start-Process -FilePath "$env:SystemRoot\System32\net.exe" -ArgumentList ("use {0} /delete /y" -f $drive) -WindowStyle Hidden -Wait | Out-Null } } catch {}
	# --- nuke exact MP2 key for *that* mapping (not the current state) ---
	try { Remove-MP2KeysetExact $Spec } catch {}
	# icon override
	try { Remove-DriveIconHKCU -DriveLetter $drive } catch {}
	if ($present) { try { Refresh-ExplorerDriveRemoval $drive } catch {} }
}
