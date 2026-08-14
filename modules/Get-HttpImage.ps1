function Get-HttpImage([string]$url, [string]$user = $null, [string]$pass = $null, [int]$timeoutMs = 3000, [string]$accept = 'image/*') {
	try {
		$req = New-HttpGetRequest $url $timeoutMs $accept
		if ($user -and $pass) { $req.Headers['Authorization'] = New-BasicAuthHeader $user $pass }
		$resp = $req.GetResponse()
		try {
			$stream = $resp.GetResponseStream()
			$img = [System.Drawing.Image]::FromStream($stream) # handles PNG/ICO/JPG
			$bmpOut = New-Object System.Drawing.Bitmap $img # clone so we can dispose $img
			$img.Dispose()
			return $bmpOut
		} finally { $resp.Close() }
	} catch { return $null }
}
