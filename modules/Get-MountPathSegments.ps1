# The path segments that follow the host: the installation path when the server
# runs in a subdirectory, the WebDAV endpoint for the mount's Kind, then the
# segments of its subfolder. That order is the order of the URL the redirector
# builds from it. UNC path, MountPoints2 key names and the pattern that
# recognizes a live mapping are all derived from this one list, which is what
# keeps the three in sync.
function Get-MountPathSegments {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$segs = @()
	$base = (Split-ServerString $Spec.Server).BasePath
	if ($base) { $segs += @(($base -split '/') | Where-Object { $_ }) }
	$segs += switch ($Spec.Kind) {
		'share' { @('public.php', 'dav', 'files', $Spec.Token) }
		'share-legacy' { @('public.php', 'webdav') }
		default { @('remote.php', 'dav', 'files', $Spec.User) }
	}
	$norm = Normalize-SubPath $Spec.SubPath
	if ($norm) { $segs += ($norm -split '/') }
	return , $segs
}
