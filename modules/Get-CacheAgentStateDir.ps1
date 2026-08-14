# The elevated agent is a process of its own, so its state sits beside the
# instance list: both ends have to be looking at the same directory.
function Get-CacheAgentStateDir {
	$dir = Join-Path (Get-StateDir) 'CacheAgent'
	if (-not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
	return $dir
}
