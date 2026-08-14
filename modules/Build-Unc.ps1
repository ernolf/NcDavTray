function Build-Unc {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	return '\\{0}\{1}' -f (Get-MountHostPart $Spec), ((Get-MountPathSegments $Spec) -join '\')
}
