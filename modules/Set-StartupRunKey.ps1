# Autostart. Name and path are parameters so an installation can switch the entry
# of the copy it just put in place rather than of the one that is running. A
# script that is not there gets no entry -- a Run value pointing at a missing file
# fails at every logon and says nothing about why.
function Set-StartupRunKey([bool]$enable, [string]$Name = $AppName, [string]$ScriptPath = $InstallBin) {
	if ($PortableMode) { return }
	if ($enable) {
		if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) { return }
		$exe, $args = Get-LauncherFor $ScriptPath
		New-ItemProperty -Path $RunKey -Name $Name -Value "`"$exe`" $args" -PropertyType String -Force | Out-Null
	}
	elseif (Get-ItemProperty -Path $RunKey -Name $Name -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RunKey -Name $Name -Force }
}