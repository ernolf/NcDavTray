# Asks the server what it makes of a share link, before anything is mounted.
# Nextcloud's shareinfo endpoint answers 404 for a token it does not know, 403
# when the password is missing or wrong, and 200 when the share is readable --
# which is exactly the difference between a mistyped link, a share that wants a
# password, and one that wants none.
# Returns 'ok', 'password', 'notfound' or 'unreachable'. The last one says the
# question could not be asked, not that the answer was no: a server that is down
# must not turn into "this link is wrong".
# The answer also names the shared file or folder, which is handed back through
# Name where a caller wants it.
function Test-ShareAccess {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][string]$Server,
		[Parameter(Mandatory)][string]$Token,
		[AllowEmptyString()][string]$Password = '',
		[ref]$Name
	)

	$body = 't={0}&password={1}' -f [uri]::EscapeDataString($Token), [uri]::EscapeDataString($Password)
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
	# The shared factory carries the TLS version, the user agent and the timeouts;
	# only the method and the body belong to this call.
	$req = New-HttpGetRequest ('https://{0}/apps/files_sharing/shareinfo' -f $Server) 6000 'application/json'
	$req.Method = 'POST'
	$req.ContentType = 'application/x-www-form-urlencoded'
	$req.ContentLength = $bytes.Length

	try {
		$stream = $req.GetRequestStream()
		try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
		$resp = $req.GetResponse()
		try {
			# Read only where the name was asked for: the answer to a shared folder
			# carries its whole listing, and the connect path has no use for any of it.
			if ($null -ne $Name) { $Name.Value = Read-ShareInfoName $resp }
			return 'ok'
		} finally { $resp.Close() }
	} catch [System.Net.WebException] {
		$resp = $_.Exception.Response
		if (-not $resp) { return 'unreachable' }
		try {
			switch ([int]$resp.StatusCode) {
				403 { return 'password' }
				404 { return 'notfound' }
				default { return 'unreachable' }
			}
		} finally { $resp.Close() }
	} catch { return 'unreachable' }
}
