# Puts the shortcut there or takes it away. An existing one is left as it is: it
# may have been moved or given an icon of the user's choosing, and rewriting it
# on every save would undo that.
function Ensure-Shortcut($which, [bool]$enable, [string]$Name = $AppName, [string]$ScriptPath = $InstallBin, [string]$IconShort = $AppNameShort) {
	if ($PortableMode) { return }
	$lnk = if ($which -eq 'StartMenu') { Get-StartMenuShortcutPath $Name } else { Get-DesktopShortcutPath $Name }
	if ($enable) {
		if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) { return }
		if (-not (Test-Path $lnk)) { New-Shortcut -lnkPath $lnk -scriptPath $ScriptPath -IconShort $IconShort }
	}
	elseif (Test-Path $lnk) { Remove-Item $lnk -Force }
}