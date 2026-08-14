# Path for persisted drive icon (.ico) derived from favicon. The file name
# carries the host, so mounts of different servers keep their own icon.
function Get-FavIconFilePath {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server )
	$safe = ($Server.ToLowerInvariant() -replace '[^a-z0-9.\-]', '_')
	return (Join-Path $HereDir ('server_favicon.{0}.ico' -f $safe))
}
