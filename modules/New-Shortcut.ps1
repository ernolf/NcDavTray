# A shortcut onto the VBS launcher rather than onto the script, so a double click
# starts the program the same way the Run key does. IconShort names the icon file
# to prefer when none is given.
function New-Shortcut($lnkPath, $scriptPath, [string]$IconPath = $null, [string]$IconShort = $AppNameShort) {
	$exe, $args = Get-LauncherFor $scriptPath; $ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($lnkPath); $sc.TargetPath = $exe; $sc.Arguments = $args
	# prefer explicit icon; otherwise try installed app ico; fallback to shell icon
	if (-not $IconPath -and -not $PortableMode) { $autoIco = Join-Path $InstallDir ("{0}.ico" -f $IconShort); if (Test-Path -LiteralPath $autoIco) { $IconPath = $autoIco } }
	if ($IconPath -and (Test-Path -LiteralPath $IconPath)) { $sc.IconLocation = "$IconPath, 0" }
	else { $sc.IconLocation = "$env:SystemRoot\system32\shell32.dll, 44" }
	$sc.WorkingDirectory = (Split-Path $scriptPath -Parent)
	$sc.Save()
}