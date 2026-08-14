# Whether this process already holds the claim on a mount, without acquiring it.
function Test-MapMutexOwned {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$name = Get-MapMutexName $Spec
	if (-not $script:MapMutexes.ContainsKey($name)) { return $false }
	return [bool]$script:MapMutexes[$name].Owned
}
