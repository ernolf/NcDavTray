# Takes a public link as it is copied out of Nextcloud and returns the server and
# the token it names, or $null if it names neither. The token is the segment that
# follows '/s/'; everything before it belongs to the server's own installation
# path and says nothing about the WebDAV endpoint.
# Only https on the standard port is accepted, because that is all the host part
# of a mount can express (see Get-MountHostPart).
function ConvertFrom-ShareLink {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Link )
	$text = $Link.Trim()
	if ([string]::IsNullOrWhiteSpace($text)) { return $null }
	# A pasted link is often missing its scheme, and without one Uri finds no host
	if ($text -notmatch '^[A-Za-z][A-Za-z0-9+.\-]*://') { $text = 'https://' + $text }
	$uri = $null
	try { $uri = [uri]$text } catch { return $null }
	if (-not $uri.IsAbsoluteUri) { return $null }
	if ($uri.Scheme -ne 'https' -or -not $uri.IsDefaultPort) { return $null }
	if ([string]::IsNullOrWhiteSpace($uri.Host)) { return $null }
	$segments = @(($uri.AbsolutePath -split '/') | Where-Object { $_ -ne '' })
	$token = ''
	for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
		if ($segments[$i] -eq 's') { $token = $segments[$i + 1]; break }
	}
	if ([string]::IsNullOrWhiteSpace($token)) { return $null }
	return [pscustomobject]@{ Server = $uri.Host; Token = [uri]::UnescapeDataString($token) }
}
