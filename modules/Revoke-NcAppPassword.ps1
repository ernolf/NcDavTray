# Withdraws an app password on the server it belongs to. The call authenticates
# with the password it is about to withdraw, and the server invalidates exactly
# that token -- there is nothing to name and nothing else that can be hit.
# A password that is not a token answers 403 'no app password in use', which is
# the same $false as any other refusal: nothing was withdrawn.
function Revoke-NcAppPassword {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User, [Parameter(Mandatory)][AllowEmptyString()][string]$Pass )
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User) -or [string]::IsNullOrWhiteSpace($Pass)) { return $false }
	try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 } catch {}
	try {
		$req = [System.Net.HttpWebRequest]::Create("https://$Server/ocs/v2.php/core/apppassword")
		$req.Method = 'DELETE'
		$req.UserAgent = "ernolfs $AppName v$Version"
		$req.Timeout = 8000
		$req.ReadWriteTimeout = 8000
		$req.AllowAutoRedirect = $true
		$req.Accept = 'application/json'
		$req.Headers['OCS-APIRequest'] = 'true'
		$req.Headers['Authorization'] = New-BasicAuthHeader $User $Pass
		$resp = $req.GetResponse()
		try { return ([int]([System.Net.HttpWebResponse]$resp).StatusCode -eq 200) } finally { try { $resp.Close() } catch {} }
	}
	catch { return $false }
}
