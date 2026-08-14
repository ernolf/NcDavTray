# Stores the DPAPI blob of one server/user pair, or removes it when there is
# nothing to store. Every mount of that pair is served by this one value, so a
# password set here is in force for all of them from the next connect on.
function Set-AccountSecret {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Server,
		[Parameter(Mandatory)][AllowEmptyString()][string]$User,
		[Parameter(Mandatory)][AllowEmptyString()][string]$EncPass
	)
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return }
	$name = Get-AccountKey -Server $Server -User $User
	if (-not $IsInstalled) {
		if ([string]::IsNullOrEmpty($EncPass)) { $script:AccountSecretCache.Remove($name) } else { $script:AccountSecretCache[$name] = $EncPass }
		return
	}
	$path = Get-AccountsRegPath
	if (-not (Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
	if ([string]::IsNullOrEmpty($EncPass)) { try { Remove-ItemProperty -LiteralPath $path -Name $name -Force -ErrorAction Stop } catch {}; return }
	New-ItemProperty -LiteralPath $path -Name $name -Value $EncPass -PropertyType String -Force | Out-Null
}