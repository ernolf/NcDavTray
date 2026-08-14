function Get-InstanceStateDir {
	$dir = Join-Path (Get-StateDir) 'Instances'
	if (-not (Test-Path -LiteralPath $dir)) { try { New-Item -ItemType Directory -Path $dir -Force | Out-Null } catch {} }
	return $dir
}
