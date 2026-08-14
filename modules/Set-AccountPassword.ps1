# Encrypts a plain password for one server/user pair and stores it, or clears the
# pair's stored password when nothing is handed in. DPAPI ties the blob to this
# user on this machine, which is what makes it safe to leave lying in the registry.
# A portable copy gets the same blob in its session table; what it puts in the file
# is another question, and Save-PortableSecretStore answers it.
function Set-AccountPassword {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Server,
		[Parameter(Mandatory)][AllowEmptyString()][string]$User,
		[Parameter(Mandatory)][AllowEmptyString()][string]$Plain
	)
	if ([string]::IsNullOrWhiteSpace($Plain)) { Set-AccountSecret -Server $Server -User $User -EncPass ''; return }
	$sec = ConvertTo-SecureString $Plain -AsPlainText -Force
	Set-AccountSecret -Server $Server -User $User -EncPass ($sec | ConvertFrom-SecureString)
}