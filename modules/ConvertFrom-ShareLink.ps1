# Takes a public link as it is copied out of Nextcloud and returns the server and
# the token it names, or $null if it names neither. The token is the segment that
# follows '/s/'; what sits in front of it is the path the instance is installed
# under and belongs in the server string, all but the 'index.php' that a link
# without pretty URLs carries.
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
	$at = -1
	for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
		if ($segments[$i] -eq 's') { $token = $segments[$i + 1]; $at = $i; break }
	}
	if ([string]::IsNullOrWhiteSpace($token)) { return $null }
	$base = @()
	if ($at -gt 0) { $base = @($segments | Select-Object -First $at) }
	if ($base.Count -gt 0 -and $base[-1] -eq 'index.php') { $base = @($base | Select-Object -First ($base.Count - 1)) }
	$server = if ($base.Count -gt 0) { '{0}/{1}' -f $uri.Host, ($base -join '/') } else { [string]$uri.Host }
	return [pscustomobject]@{ Server = $server; Token = [uri]::UnescapeDataString($token) }
}
