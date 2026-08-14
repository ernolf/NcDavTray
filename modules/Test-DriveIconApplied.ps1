function Test-DriveIconApplied {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$DriveLetter, [Parameter(Mandatory)][string]$IconPath )
	# Cheap existence/value check via .NET (more robust than provider)
	if (-not ($DriveLetter -match '^[A-Za-z]:$')) { return $false }; if (-not (Test-Path -LiteralPath $IconPath)) { return $false }
	$dl = $DriveLetter.Substring(0, 1).ToUpper()
	try {
		$cu = [Microsoft.Win32.Registry]::CurrentUser
		$def = $cu.OpenSubKey("Software\Classes\Applications\Explorer.exe\Drives\$dl\DefaultIcon", $false)
		if ($null -eq $def) { return $false }
		$val = $def.GetValue('')
		$def.Close()
		return ($val -and ($val -ieq "$IconPath, 0"))
	} catch { return $false }
}
