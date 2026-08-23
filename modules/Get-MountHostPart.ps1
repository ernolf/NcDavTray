# The host part of a UNC path. Never more than the host: an instance that sits
# in a subdirectory carries that path in its segments, because the redirector
# reads everything up to the first backslash as the server to talk to.
function Get-MountHostPart {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$h = (Split-ServerString $Spec.Server).Host
	if ($Spec.ExplicitPort) { return '{0}@ssl@443' -f $h }
	return '{0}@ssl' -f $h
}
