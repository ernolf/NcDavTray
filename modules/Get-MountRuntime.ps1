# Per-mount data that is never persisted, created on first access. It is keyed by
# the entry's Id rather than by the mount key, so it survives an edit of the drive
# letter or the subfolder.
# Pass distinguishes three states: $null means nothing has been asked for yet, an
# empty string means the share has no password, anything else is the password.
function Get-MountRuntime {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Id )
	if (-not $script:Runtime.ContainsKey($Id)) { $script:Runtime[$Id] = [pscustomobject]@{ Pass = $null } }
	return $script:Runtime[$Id]
}
