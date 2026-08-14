function Normalize-SubPath([string]$sp) {
	if ([string]::IsNullOrWhiteSpace($sp) -or $sp -eq '/') { return '' }
	$sp = $sp.Trim().Trim('/', '\')
	if ($sp.Length -eq 0) { return '' }
	# Combine multiple / or \ -> save with '/'
	$parts = ($sp -split '[\\/]+') | Where-Object { $_ -ne '' }
	return ($parts -join '/')
}
