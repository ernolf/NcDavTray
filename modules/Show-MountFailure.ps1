# Says why a mount did not come up. Silence is the worst possible answer here: a
# drive that stays red without a word leaves the user nothing to act on, and the
# return code of WNetAddConnection2 is the only thing that knows the difference.
# Only the codes with a remedy of their own get a text of their own; everything
# else carries the number, which is what the event log and a search engine speak.
function Show-MountFailure {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Entry, [int]$Code )
	$vars = @{ share = (Get-MountDisplayName $Entry); server = $Entry.Server; drive = $Entry.Drive; code = $Code }
	switch ($Code) {
		# ERROR_SESSION_CREDENTIAL_CONFLICT -- both server identities are spoken for
		1219 { Show-CredentialConflict -Server $Entry.Server -Drive $Entry.Drive -Code $Code -Share (Get-MountDisplayName $Entry) }
		# ERROR_ACCESS_DENIED / ERROR_LOGON_FAILURE / ERROR_NOT_AUTHENTICATED
		5 { Show-WarnT 'message.mount_credentials_rejected' $vars }
		1326 { Show-WarnT 'message.mount_credentials_rejected' $vars }
		1244 { Show-WarnT 'message.mount_credentials_rejected' $vars }
		# ERROR_BAD_NETPATH / ERROR_BAD_NET_NAME
		53 { Show-WarnT 'message.mount_server_unreachable' $vars }
		67 { Show-WarnT 'message.mount_server_unreachable' $vars }
		# ERROR_GEN_FAILURE / ERROR_UNEXP_NET_ERR -- the server answered, but with
		# something the redirector cannot make a DAV session out of
		31 { Show-WarnT 'message.mount_network_error' $vars }
		59 { Show-WarnT 'message.mount_network_error' $vars }
		default { Show-WarnT 'message.mount_failed' $vars }
	}
}
