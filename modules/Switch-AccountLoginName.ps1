# Puts every mount of one account on another login name, and the account's stored
# password with it. Both names reach the same files, but the redirector keys its
# session on the string it was handed, so two spellings of one account occupy two
# of the two identities a host has -- see Get-MountHostPart for what that limit is.
# NewPlain has to be an app password that was fetched under NewUser: a token
# carries the login name it was created with and is refused under any other, which
# is why this cannot simply rename the pair and keep the password it had.
# The password of the old spelling is withdrawn on the server, because after this
# nothing uses it.
function Switch-AccountLoginName {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$OldUser, [Parameter(Mandatory)][string]$NewUser, [Parameter(Mandatory)][AllowEmptyString()][string]$NewPlain )
	$affected = @(Get-AccountMounts -Server $Server -User $OldUser)
	# Read before the store is written: this is what the old spelling was signing in
	# with, and the only thing that can withdraw it afterwards.
	$oldPlain = Unprotect-MountSecret -Entry ([pscustomobject]@{ Server = $Server; Kind = 'account'; User = $OldUser; Token = '' })
	if (-not [string]::IsNullOrWhiteSpace($NewPlain)) { Set-AccountPassword -Server $Server -User $NewUser -Plain $NewPlain }
	# What the affected mounts are mapped under right now. Built before the entries
	# are rewritten, because afterwards there is nothing left to describe them with.
	$old = @()
	foreach ($e in $affected) { $old += (New-MountSpecFromEntry $e) }
	foreach ($e in $affected) {
		$e.User = $NewUser
		# The password of a running mount is held per Id and would otherwise be the one
		# that was just withdrawn.
		(Get-MountRuntime ([string]$e.Id)).Pass = $null
	}
	Save-Config
	[void](Remove-UnusedAccountSecret -Server $Server -User $OldUser)
	if ($PortableMode) { [void](Save-PortableSecretStore) }
	if (-not [string]::IsNullOrEmpty($oldPlain) -and ($oldPlain -cne $NewPlain)) { [void](Revoke-NcAppPassword -Server $Server -User $OldUser -Pass $oldPlain) }
	# A mapped drive still carries the old login name in its path, so it has to go
	# down before the new one can take the letter -- the same sequence a changed
	# server or subfolder goes through, see Set-AccountEditorContext.
	for ($i = 0; $i -lt $old.Count; $i++) {
		$spec = $old[$i]
		if ([string]::IsNullOrWhiteSpace($spec.Drive)) { continue }
		try { Unmap-DriveIfOurs -Spec $spec -Force -RemoveProfile } catch {}
		try { Refresh-ExplorerDriveRemoval $spec.Drive } catch {}
		try { Remove-MapMutex -Spec $spec } catch {}
		try { Remove-DriveGuard -Drive $spec.Drive } catch {}
		[void](Wait-DriveFullyUnmapped -Drive $spec.Drive -TimeoutMs 3000)
	}
	foreach ($e in $affected) { if ($e.Enabled) { Connect-MountById ([string]$e.Id) } }
}
