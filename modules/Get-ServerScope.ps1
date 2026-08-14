# Returns "Local", "Internet" or "Unknown"
function Get-ServerScope([string]$Server) {
	$Server = ($Server -as [string]).Trim()
	if (-not $Server) { return 'Unknown' }
	# Server is stored without scheme by design -> always treat as HTTPS URL
	$url = "https://$Server"; $uri = $null
	if (-not [System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$uri)) { return 'Unknown' }
	try { $zone = [System.Security.Policy.Zone]::CreateFromUrl($uri.AbsoluteUri) } catch { return 'Unknown' }
	switch ($zone.SecurityZone) { 'MyComputer' { return 'Local' }; 'Intranet' { return 'Local' }; default { return 'Internet' } }
}
