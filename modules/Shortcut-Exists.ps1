# Whether the named program has the shortcut asked about.
function Shortcut-Exists($which, [string]$Name = $AppName) {
	if ($PortableMode) { return $false }
	$lnk = if ($which -eq 'StartMenu') { Get-StartMenuShortcutPath $Name } else { Get-DesktopShortcutPath $Name }
	return (Test-Path $lnk)
}