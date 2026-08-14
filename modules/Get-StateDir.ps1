# The one directory every running instance agrees on. Keyed on the application
# name and not on the folder the script sits in, because every portable copy would
# otherwise keep a state of its own. LocalApplicationData makes it per user
# session, which is the scope processes and their PIDs actually live in.
function Get-StateDir {
	$base = [Environment]::GetFolderPath('LocalApplicationData')
	$dir = Join-Path $base $AppName
	if (-not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
	return $dir
}
