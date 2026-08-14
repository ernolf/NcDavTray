# Asks whether the share page exists, which is the one question shareinfo leaves
# open. A server that hands out no public shares over WebDAV answers 404 to
# shareinfo for every token, valid or not, while the page it serves in a browser
# is untouched by that setting -- so a page that answers means the token is good
# and the server is the problem.
# Returns 'ok', 'notfound' or 'unreachable'. Nothing of the page is read: only
# whether the server produced one.
function Test-SharePage {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Server,
		[Parameter(Mandatory)][string]$Token
	)

	$req = New-HttpGetRequest ('https://{0}/s/{1}' -f $Server, [uri]::EscapeDataString($Token)) 6000 'text/html'
	try {
		$resp = $req.GetResponse()
		try { return 'ok' } finally { $resp.Close() }
	} catch [System.Net.WebException] {
		$resp = $_.Exception.Response
		if (-not $resp) { return 'unreachable' }
		try {
			if ([int]$resp.StatusCode -eq 404) { return 'notfound' }
			return 'unreachable'
		} finally { $resp.Close() }
	} catch { return 'unreachable' }
}