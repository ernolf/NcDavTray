# True when a URL is https and points at the host it is supposed to point at.
function Test-SameHostHttps([string]$Url, [string]$ExpectedHost) {
	if ([string]::IsNullOrWhiteSpace($Url) -or [string]::IsNullOrWhiteSpace($ExpectedHost)) { return $false }
	$u = $null
	try { $u = [Uri]$Url } catch { return $false }
	if ($u.Scheme -ne 'https') { return $false }
	return [string]::Equals($u.Host, $ExpectedHost.Trim().Trim('/'), 'OrdinalIgnoreCase')
}
