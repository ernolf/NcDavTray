# Canonical lower-case identity of a mount, for everything that needs a name
# per mount rather than per process: mutex names, per-mount file names. Two
# specs addressing the same target on the same drive letter yield the same key.
function Get-MountKey {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$parts = @($Spec.Drive, (Get-MountHostPart $Spec)) + (Get-MountPathSegments $Spec)
	return (($parts -join ':').ToLowerInvariant())
}
