# Adapter between a persisted mount entry and the MountSpec the mapping functions
# take. The entry is the configuration record and may grow fields the mapping core
# knows nothing about, which is why the two are not the same object.
function New-MountSpecFromEntry {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	return New-MountSpec -Server $Entry.Server -Kind $Entry.Kind -User $Entry.User -Token $Entry.Token -SubPath $Entry.SubPath -Drive $Entry.Drive -Label $Entry.Label -ExplicitPort:$Entry.ExplicitPort
}