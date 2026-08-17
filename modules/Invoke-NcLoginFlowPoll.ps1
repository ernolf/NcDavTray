# One poll of a running Login Flow v2 session. The server answers 404 for as long
# as the login has not been confirmed in the browser, and 200 exactly once
# afterwards -- the token is spent with that one answer.
# State is 'Pending', 'Ok' or 'Failed'.
function Invoke-NcLoginFlowPoll {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Endpoint, [Parameter(Mandatory)][string]$Token )
	$pending = [pscustomobject]@{ State = 'Pending'; Server = $null; LoginName = $null; AppPassword = $null }
	$failed = [pscustomobject]@{ State = 'Failed'; Server = $null; LoginName = $null; AppPassword = $null }
	try {
		$body = 'token=' + [System.Uri]::EscapeDataString($Token)
		$req = New-HttpPostRequest $Endpoint $body 8000
		$raw = $null
		$resp = $req.GetResponse()
		try {
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
		} finally { try { $resp.Close() } catch {} }
		$j = $null
		try { $j = $raw | ConvertFrom-Json } catch {}
		if (-not $j -or [string]::IsNullOrWhiteSpace($j.loginName) -or [string]::IsNullOrWhiteSpace($j.appPassword)) { return $failed }
		return [pscustomobject]@{ State = 'Ok'; Server = [string]$j.server; LoginName = [string]$j.loginName; AppPassword = [string]$j.appPassword }
	}
	catch [System.Net.WebException] {
		$code = $null
		try { $http = [System.Net.HttpWebResponse]$_.Exception.Response; if ($http) { $code = [int]$http.StatusCode } } catch {}
		if ($code -eq 404) { return $pending }
		# No status code at all means the request never reached the server. The login
		# in the browser is untouched by that, so a dropped connection waits rather
		# than throwing a session away that may still be confirmed.
		if ($null -eq $code) { return $pending }
		return $failed
	}
	catch { return $pending }
}
