# The path segments that follow the host: the WebDAV endpoint for the mount's
# Kind, then the segments of its subfolder. UNC path, MountPoints2 key names and
# the pattern that recognizes a live mapping are all derived from this one list,
# which is what keeps the three in sync.
function Get-MountPathSegments {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$segs = switch ($Spec.Kind) {
		'share' { @('public.php', 'dav', 'files', $Spec.Token) }
		'share-legacy' { @('public.php', 'webdav') }
		default { @('remote.php', 'dav', 'files', $Spec.User) }
	}
	$norm = Normalize-SubPath $Spec.SubPath
	if ($norm) { $segs += ($norm -split '/') }
	return , $segs
}
