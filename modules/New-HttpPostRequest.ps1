# Shared POST request factory -- same defaults as New-HttpGetRequest, plus the
# form body. The user agent is a parameter here and nowhere else: Nextcloud files
# an app password under the name of the client that asked for it, so a request
# that creates one has to be able to say what that name is.
function New-HttpPostRequest([string]$uri, [string]$body = '', [int]$timeoutMs = 8000, [string]$accept = 'application/json', [string]$userAgent = $null) {
	try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}
	$req = [System.Net.HttpWebRequest]::Create($uri)
	$req.Method = 'POST'
	$req.UserAgent = $(if ([string]::IsNullOrWhiteSpace($userAgent)) { "ernolfs $AppName v$Version" } else { $userAgent })
	$req.Timeout = $timeoutMs
	$req.ReadWriteTimeout = $timeoutMs
	$req.AllowAutoRedirect = $true
	$req.Accept = $accept
	$req.ContentType = 'application/x-www-form-urlencoded'
	$bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
	$req.ContentLength = $bytes.Length
	# Written here rather than by the caller: a POST that goes out before its body
	# is on the stream answers before anyone can add one.
	$s = $req.GetRequestStream()
	try { if ($bytes.Length -gt 0) { $s.Write($bytes, 0, $bytes.Length) } } finally { $s.Close() }
	return $req
}
