# RAW OCS folder-tree call that returns status code + raw + parsed JSON.
function Invoke-NcOcsFolderTreeRaw {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$User, [Parameter(Mandatory)][string]$Pass, [string]$EncodedPath, [int]$Depth = 0 )
	$uri = "https://$Server/ocs/v2.php/apps/files/api/v1/folder-tree?depth=$Depth"
	if ($null -ne $EncodedPath) { $uri += "&path=$EncodedPath" } else { $uri += "&path=%2F" }
	try {
		$req = New-HttpGetRequest $uri
		$req.Headers['OCS-APIRequest'] = 'true'
		$req.Headers['Authorization'] = New-BasicAuthHeader $User $Pass
		$resp = $req.GetResponse()
		try {
			$code = [int]([System.Net.HttpWebResponse]$resp).StatusCode
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
			$obj = $null
			try { $obj = $raw | ConvertFrom-Json } catch {}
			return [pscustomobject]@{ StatusCode = $code; BodyRaw = $raw; Json = $obj }
		} finally { try { $resp.Close() } catch {} }
	}
	catch [System.Net.WebException] {
		$code = $null; $raw = $null; $obj = $null
		try {
			$http = [System.Net.HttpWebResponse]$_.Exception.Response
			if ($http) {
				$code = [int]$http.StatusCode
				$sr = New-Object System.IO.StreamReader($http.GetResponseStream())
				$raw = $sr.ReadToEnd()
				$sr.Close()
				if (-not [string]::IsNullOrWhiteSpace($raw)) { try { $obj = $raw | ConvertFrom-Json } catch {} }
			}
		} catch {}
		return [pscustomobject]@{ StatusCode = $code; BodyRaw = $raw; Json = $obj }
	}
	catch { return [pscustomobject]@{ StatusCode = $null; BodyRaw = $null; Json = $null } }
}
