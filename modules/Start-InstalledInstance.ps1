# Starts the copy that was just installed, exactly once. Nothing is handed to it
# on the command line: it brings its own watchdog up and reads its configuration
# where an installed copy reads it anyway. The working directory is the install
# folder, not the one the installer was run from -- a process holds its directory
# open, and that one is usually the folder the user deletes next.
function Start-InstalledInstance {
	[CmdletBinding()] param()
	try {
		if (-not (Test-Path -LiteralPath $InstallBin)) { return $false }
		$exe, $args = Get-LauncherFor $InstallBin
		Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $InstallDir -WindowStyle Hidden | Out-Null
		return $true
	} catch { return $false }
}