# The user id of the account the given credentials belong to. It has to be asked
# for: Nextcloud accepts a verified mail address as a login name, and what a login
# hands back is the name that was typed, not the id behind it. Both reach the same
# files, but they are two spellings of one account, and each spelling that gets
# used costs a stored password and a Windows login of its own.
# Returns '' when the server does not answer with one -- an older server, a
# provisioning API that is switched off -- and the caller then keeps the name it
# already has.
function Get-NcUserId {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User, [Parameter(Mandatory)][AllowEmptyString()][string]$Pass )
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) { return '' }
	$raw = ''
	try {
		$req = New-HttpGetRequest "https://$Server/ocs/v2.php/cloud/user?format=json" 8000
		$req.Headers['OCS-APIRequest'] = 'true'
		$req.Headers['Authorization'] = New-BasicAuthHeader $User $Pass
		$resp = $req.GetResponse()
		try {
			if ([int]([System.Net.HttpWebResponse]$resp).StatusCode -ne 200) { return '' }
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
		} finally { try { $resp.Close() } catch {} }
		$id = ''
		try { $id = [string]($raw | ConvertFrom-Json).ocs.data.id } catch {}
		return $id.Trim()
	}
	catch { return '' }
}
