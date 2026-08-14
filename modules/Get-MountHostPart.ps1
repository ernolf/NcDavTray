function Get-MountHostPart {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	if ($Spec.ExplicitPort) { return '{0}@ssl@443' -f $Spec.Server }
	return '{0}@ssl' -f $Spec.Server
}
