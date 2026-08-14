function Get-CacheAgentState {
	# Reads current state.json from the cache agent (if present)
	$path = Get-CacheAgentStatePath
	if (-not (Test-Path -LiteralPath $path)) { return $null }
	try { $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop; if (-not $raw) { return $null }; return ($raw | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}
