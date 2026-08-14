function Remove-DriveIconHKCU {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$DriveLetter )
	if (-not ($DriveLetter -match '^[A-Za-z]:$')) { return }
	$dl = $DriveLetter.Substring(0, 1).ToUpper()
	# Delete HKCU\Software\Classes\Applications\Explorer.exe\Drives\<X>\* (keep ...\Drives)
	try { $cu = [Microsoft.Win32.Registry]::CurrentUser; $base = $cu.OpenSubKey('Software\Classes\Applications\Explorer.exe\Drives', $true); if ($base) { try { $base.DeleteSubKeyTree($dl, $false) } catch {}; $base.Close() } } catch {}
	try { Refresh-ShellIcons } catch {}
}
