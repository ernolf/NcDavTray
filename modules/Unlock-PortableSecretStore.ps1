# The one passphrase question of the run, asked before the first mount is tried:
# a mount without its password is a red drive letter, and a question that comes
# after it explains none of what the user has already seen go wrong.
# A wrong answer is asked again -- the file is still there and still readable, it
# was the typing that failed. Cancelling ends the program instead of carrying on
# without the passwords: every account would then ask for its own, which is the
# opposite of what the file is for.
# Returns whether the program should go on.
function Unlock-PortableSecretStore {
	[CmdletBinding()] param()
	if ($IsInstalled) { return $true }
	if (-not (Test-Path -LiteralPath $SecretPath)) { return $true }
	while ($true) {
		$pp = Prompt-Passphrase -Title (T 'title.passphrase_query' @{ app = $AppName })
		if ($null -eq $pp) { return $false }
		try {
			$rewrite = Read-PortableSecretStore -Passphrase $pp
			$script:SecretPassphrase = $pp
			if ($rewrite) { [void](Save-PortableSecretStore) }
			return $true
		} catch { Show-WarnT 'message.passphrase_wrong_or_corrupt' }
	}
}