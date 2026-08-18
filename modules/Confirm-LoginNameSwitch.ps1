# Asks before an account is moved onto its user id, but only when the move is
# going to be felt: a connected mount has to go down and come back up, and an
# application holding a file open on it loses that file. With nothing connected
# there is nothing to weigh up and the question would be noise.
function Confirm-LoginNameSwitch {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$OldUser, [Parameter(Mandatory)][string]$NewUser )
	$live = $false
	foreach ($e in @(Get-AccountMounts -Server $Server -User $OldUser)) {
		if (-not $e.Enabled) { continue }
		if (Test-DriveMatchesDesired -Spec (New-MountSpecFromEntry $e)) { $live = $true; break }
	}
	if (-not $live) { return $true }
	return ((Ask-YesNoQuestT 'prompt.login_name_switch' @{ old = $OldUser; id = $NewUser }) -eq [System.Windows.Forms.DialogResult]::Yes)
}
