# Unified server status via /status.php (no auth)
function Get-NcServerStatus {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server )
	$fail = [pscustomobject]@{ Reachable = $false; Maintenance = $false; Installed = $false; Json = $null }
	if ([string]::IsNullOrWhiteSpace($Server)) { return $fail }
	$uri = "https://$Server/status.php"
	try {
		$req = New-HttpGetRequest $uri
		$resp = $req.GetResponse()
		try {
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
			$j = $null
			try { $j = $raw | ConvertFrom-Json } catch {}
			$installed = $false; $maint = $false
			if ($j) {
				if ($j.PSObject.Properties.Name -contains 'installed') { $installed = [bool]$j.installed }
				if ($j.PSObject.Properties.Name -contains 'maintenance') { $maint = [bool]$j.maintenance }
			}
			return [pscustomobject]@{ Reachable = $true; Maintenance = $maint; Installed = $installed; Json = $j }
		} finally { try { $resp.Close() } catch {} }
	} catch { return $fail }
}
