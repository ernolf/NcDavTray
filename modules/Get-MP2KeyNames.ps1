# The MountPoints2 key names Explorer may use for a mount, canonical one first.
# Built exactly like Explorer does it: no drive letter, literal '#' between path
# parts, optional DavWWWRoot prefix.
function Get-MP2KeyNames {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$hostPart = Get-MountHostPart $Spec
	$path = (Get-MountPathSegments $Spec) -join '#'
	return @(
		('##{0}#{1}' -f $hostPart, $path),
		('##{0}#DavWWWRoot#{1}' -f $hostPart, $path)
	)
}
