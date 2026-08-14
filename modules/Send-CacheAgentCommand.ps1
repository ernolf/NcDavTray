function Send-CacheAgentCommand([Parameter(Mandatory = $true)][hashtable]$Command) {
	$path = Get-CacheAgentCommandPath; $tmp = $path + '.tmp'
	try { $json = $Command | ConvertTo-Json -Depth 4; $json | Set-Content -LiteralPath $tmp -Encoding UTF8; Move-Item -LiteralPath $tmp -Destination $path -Force; return $true } catch { return $false }
}
