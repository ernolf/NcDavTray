# What the secret file of a package being exported has to hold, and the passphrase
# that will protect it -- both settled before the first file is written, because a
# package abandoned half way at the passphrase question is worse than one that was
# never begun.
# The passwords are read the way every other reader reads them, so an installed
# copy hands over what its Accounts key holds and a portable one what its own file
# was unlocked into. The passphrase is not kept: it belongs to the package, not to
# the copy that wrote it.
# Returns $null when the question was declined. An empty Json means there is
# nothing stored to take along -- an empty container would ask for a passphrase on
# every start of the package and hand back nothing for it.
function Get-PortableSecretPayload {
	[CmdletBinding()] param()
	$tab = @{}
	foreach ($e in @($State.Mounts)) {
		if (-not $e) { continue }
		$plain = Unprotect-MountSecret -Entry $e
		if ([string]::IsNullOrEmpty($plain)) { continue }
		$tab[(Get-AccountKey -Server $e.Server -User (Get-MountSecretName $e))] = $plain
	}
	if ($tab.Count -eq 0) { return [pscustomobject]@{ Json = ''; Passphrase = $null } }
	$pp = Prompt-Passphrase -Title (T 'title.passphrase_set' @{ app = $AppName }) -Confirm
	if ([string]::IsNullOrEmpty($pp)) { Show-WarnT 'message.passphrase_required'; return $null }
	return [pscustomobject]@{ Json = ($tab | ConvertTo-Json -Depth 2); Passphrase = $pp }
}