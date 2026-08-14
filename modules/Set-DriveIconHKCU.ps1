function Set-DriveIconHKCU {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$DriveLetter, [Parameter(Mandatory)][string]$IconPath )
	# Validate
	if (-not ($DriveLetter -match '^[A-Za-z]:$')) { return }; if (-not (Test-Path -LiteralPath $IconPath)) { return }
	$dl = $DriveLetter.Substring(0, 1).ToUpper()
	# Create full key chain under HKCU\Software\Classes\Applications\Explorer.exe\Drives\<X>\DefaultIcon
	try {
		$cu = [Microsoft.Win32.Registry]::CurrentUser
		$apps = $cu.CreateSubKey('Software\Classes\Applications', $true)
		$exp = $apps.CreateSubKey('Explorer.exe', $true)
		$drvS = $exp.CreateSubKey('Drives', $true)
		$drv = $drvS.CreateSubKey($dl, $true)
		$def = $drv.CreateSubKey('DefaultIcon', $true)
		# Write (Default) as REG_SZ with "<path>, 0"
		$def.SetValue('', "$IconPath, 0", [Microsoft.Win32.RegistryValueKind]::String)
		# Close handles
		$def.Close(); $drv.Close(); $drvS.Close(); $exp.Close(); $apps.Close()
	} catch {} # Swallow, timer will retry
	try { Refresh-ShellIcons } catch {} # Nudge the shell
}
