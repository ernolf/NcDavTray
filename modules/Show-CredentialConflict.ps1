# Says what error 1219 really means, and names the drives holding the two
# identities where Windows knows a letter for them -- a connection made without
# one takes the identity just the same but has nothing to be called by. The
# situation belongs to the host and not to the mount that ran into it: the one
# that has to give way may well be another.
function Show-CredentialConflict {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$Drive, [int]$Code = 1219, [AllowEmptyString()][string]$Share = '' )
	$idents = Get-UsedServerIdentities -Server $Server
	$drives = @($idents.Drives)
	$vars = @{ server = $Server; drive = $Drive; code = $Code; share = $Share; drives = ($drives -join (' {0} ' -f (T 'label.list_and'))) }
	if ($drives.Count -gt 0) { Show-WarnT 'message.mount_credential_conflict_drives' $vars }
	else { Show-WarnT 'message.mount_credential_conflict' $vars }
}