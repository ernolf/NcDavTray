# Drops a stored password once the last mount using it is gone. The value outlives
# the mount by design -- an account password serves every mount of its pair, and a
# duplicated share carries the token of the one it was copied from -- so the last
# one to go is what settles it. User is the name from Get-MountSecretName.
# Called after the entry has been removed from the store, so what is still listed
# is what still needs the password.
function Remove-UnusedAccountSecret {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Server,
		[Parameter(Mandatory)][AllowEmptyString()][string]$User
	)
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return }
	$key = Get-AccountKey -Server $Server -User $User
	foreach ($e in @(Read-MountEntriesFromRegistry)) {
		if (-not $e) { continue }
		if ((Get-AccountKey -Server $e.Server -User (Get-MountSecretName $e)) -eq $key) { return }
	}
	Set-AccountSecret -Server $Server -User $User -EncPass ''
}