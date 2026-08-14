# Asks whether any live instance holds a role, without building the list of
# them. This is what a detached helper polls to decide whether it is still
# needed, so it runs on every tick and stays as cheap as the pruning read.
function Test-AnyInstanceRole([Parameter(Mandatory)][string]$Role) {
	$alive = Get-AliveInstanceEntries
	if (-not $alive) { return $false }
	foreach ($e in $alive) { if ([string]$e.Role -eq $Role) { return $true } }
	return $false
}
