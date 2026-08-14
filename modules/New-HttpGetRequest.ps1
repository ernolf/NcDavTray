# Shared GET request factory — sets TLS 1.2, UA, timeout, redirect, and Accept.
function New-HttpGetRequest([string]$uri, [int]$timeoutMs = 4000, [string]$accept = 'application/json') {
	try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}
	$req = [System.Net.HttpWebRequest]::Create($uri)
	$req.Method = 'GET'
	$req.UserAgent = "ernolfs $AppName v$Version"
	$req.Timeout = $timeoutMs
	$req.ReadWriteTimeout = $timeoutMs
	$req.AllowAutoRedirect = $true
	$req.Accept = $accept
	return $req
}
