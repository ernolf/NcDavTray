function Get-InstanceEntriesByRole([Parameter(Mandatory)][string]$Role) {
	$alive = Get-AliveInstanceEntries
	$hits = @()
	if ($alive) { foreach ($e in $alive) { if ([string]$e.Role -eq $Role) { $hits += $e } } }
	Write-Verbose ("[Instances] Get-InstanceEntriesByRole: {0} entries for role {1}" -f $hits.Count, $Role)
	return $hits
}
