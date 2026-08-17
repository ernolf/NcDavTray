# Opens a Login Flow v2 session on the server: the URL the user has to visit in
# the browser, and the endpoint to poll while they are over there.
# Returns $null when the server does not answer with a usable session.
function Start-NcLoginFlow {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server )
	$srv = $Server.Trim().Trim('/')
	if ([string]::IsNullOrWhiteSpace($srv)) { return $null }
	# This is what the app password is filed under in 'Devices & sessions'. The major
	# version is part of it because a 2.x line stays one device; the patch level is
	# not, or every update would leave another entry behind on the server.
	$agent = ('{0} v{1}' -f $AppName, (($Version -split '\.')[0]))
	try {
		$req = New-HttpPostRequest ("https://{0}/index.php/login/v2" -f $srv) '' 8000 'application/json' $agent
		$raw = $null
		$resp = $req.GetResponse()
		try {
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
		} finally { try { $resp.Close() } catch {} }
		$j = $null
		try { $j = $raw | ConvertFrom-Json } catch {}
		if (-not $j -or -not $j.login -or -not $j.poll -or [string]::IsNullOrWhiteSpace($j.poll.token) -or [string]::IsNullOrWhiteSpace($j.poll.endpoint)) { return $null }
		# Both URLs come out of the answer: one is opened in the browser, the other is
		# where the token goes. Neither is followed unless it is https on the host that
		# was asked, so nothing in the answer can move either of them somewhere else.
		if (-not (Test-SameHostHttps ([string]$j.login) $srv)) { return $null }
		if (-not (Test-SameHostHttps ([string]$j.poll.endpoint) $srv)) { return $null }
		return [pscustomobject]@{ LoginUrl = [string]$j.login; PollEndpoint = [string]$j.poll.endpoint; PollToken = [string]$j.poll.token }
	} catch { return $null }
}
