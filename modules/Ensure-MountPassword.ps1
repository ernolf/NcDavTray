# Makes sure the runtime entry for this mount holds an answer to the password
# question, and reports whether there is one now. The server is asked first, so a
# share without a password is never asked about and a wrong one is caught here
# instead of surfacing as a drive letter that stays red for no stated reason.
# Cancelling leaves Pass at $null, so the next call asks again -- there is no
# "asked and gave up" state, because giving up is not persistent.
# Set (Get-MountRuntime $Id).Pass back to $null to force a new prompt, which is
# what a password the server rejected calls for.
function Ensure-MountPassword {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry )
	$rt = Get-MountRuntime $Entry.Id
	if ($null -ne $rt.Pass) { return $true }

	# An account signs in with the password of its server/user pair, and there is no
	# asking for it here: the settings page of the mount is where a password is
	# entered, and it is the same page for every mount of that pair. Without one the
	# mount cannot come up, and saying so is more use than a prompt whose answer
	# would be gone again by the next connect.
	if ($Entry.Kind -eq 'account') {
		$pass = Unprotect-MountSecret -Entry $Entry
		if ([string]::IsNullOrEmpty($pass)) { Show-WarnT 'message.account_password_missing' @{ mount = (Get-MountDisplayName $Entry) }; return $false }
		$rt.Pass = $pass
		return $true
	}

	$state = Test-ShareAccess -Server $Entry.Server -Token $Entry.Token
	if ($state -eq 'ok') { $rt.Pass = ''; return $true }
	if ($state -eq 'notfound') { Show-WarnT 'message.share_not_found' @{ share = (Get-MountDisplayName $Entry) }; return $false }

	# A password protected share cannot be reached over /public.php/dav/files: its
	# authentication runs through PublicAuth, which rejects any request that carries
	# a session cookie without the SameSite cookies beside it -- and the Windows
	# redirector stores the one and not the others. The answer is a 302 to the share
	# page, which no DAV client can use, and the mount fails with a network error.
	# The legacy endpoint takes the token as the login name and never reaches that
	# check, so it is the route for exactly these shares. Which one a share needs is
	# the server's business, not the user's, and it is settled here on every connect
	# rather than stored: a share that gains or loses its password stays mountable.
	# Only one direction is switched -- an entry already on the legacy endpoint may
	# be there because its server predates the modern one, and that is not ours to
	# undo.
	if ($state -eq 'password') { $Entry.Kind = 'share-legacy' }

	# A password kept from an earlier connect is tried before anyone is asked for
	# one. Where the server can be asked, one that no longer fits leads to the
	# prompt rather than to a mount that fails without saying why.
	$saved = Unprotect-MountSecret -Entry $Entry
	if (-not [string]::IsNullOrEmpty($saved)) {
		if ($state -ne 'password') { $rt.Pass = $saved; return $true }
		if ((Test-ShareAccess -Server $Entry.Server -Token $Entry.Token -Password $saved) -ne 'password') { $rt.Pass = $saved; return $true }
	}

	# 'password' and 'unreachable' both end up asking. For the unreachable server
	# the answer cannot be checked, so it is taken as given and the mount attempt
	# is what finds out; for the other one a rejected password is worth saying so
	# right away rather than after a failed mount.
	while ($true) {
		$answer = Show-SharePasswordPrompt -Entry $Entry
		if ($null -eq $answer) { return $false }
		if (($state -ne 'password') -or ((Test-ShareAccess -Server $Entry.Server -Token $Entry.Token -Password $answer.Pass) -ne 'password')) {
			$rt.Pass = $answer.Pass
			# Only what the server took is worth keeping, so this is where it is kept.
			if ($answer.Save) { Set-AccountPassword -Server $Entry.Server -User (Get-MountSecretName $Entry) -Plain $answer.Pass }
			return $true
		}
		Show-WarnT 'message.share_password_wrong'
	}
}