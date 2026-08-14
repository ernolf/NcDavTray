# The passphrase of this run, asked for once and then in force for everything --
# unlocking what is already stored and protecting what is stored from here on.
# Asked with a confirmation, because this is the path where a new one is set: at
# startup the file itself checks the answer, here nothing would catch a typo
# until the day the passwords are needed again.
function Ensure-SecretPassphrase {
	[CmdletBinding()] param()
	if ($script:SecretPassphrase) { return $true }
	$pp = Prompt-Passphrase -Title (T 'title.passphrase_set' @{ app = $AppName }) -Confirm
	if ([string]::IsNullOrEmpty($pp)) { Show-WarnT 'message.passphrase_required'; return $false }
	$script:SecretPassphrase = $pp
	return $true
}