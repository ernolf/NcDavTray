# The DPAPI blob of one server/user pair, or an empty string when that pair has
# none. An installed copy reads the Accounts key, a portable one the table its
# secret file was unlocked into at startup. Either way a pair answered once is
# answered for every mount that shares it.
function Get-AccountSecret {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User )
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return '' }
	$name = Get-AccountKey -Server $Server -User $User
	if (-not $IsInstalled) {
		if ($script:AccountSecretCache.ContainsKey($name)) { return [string]$script:AccountSecretCache[$name] }
		return ''
	}
	$path = Get-AccountsRegPath
	if (-not (Test-Path -LiteralPath $path)) { return '' }
	try {
		$props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
		if ($props.PSObject.Properties.Name -contains $name) { return [string]$props.$name }
	} catch {}
	return ''
}