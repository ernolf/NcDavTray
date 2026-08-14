# One persisted mount. Id survives edits of every other field and is what ties a
# configuration row to its tray icon and its runtime data; the mount key cannot do
# that, because it changes as soon as the drive letter or the subfolder changes.
# Kind says which field carries the mount: a share is named by its Token, an
# account by its User. The field the kind does not use stays empty instead of
# being absent, so an entry edited from one kind into the other keeps its shape.
# ExplicitPort defaults to on: a share mounted next to an account mapping of the
# same server needs the second server identity, and that is the normal case here.
function New-MountEntry {
	[CmdletBinding()]
	param(
		[string]$Id = '',
		[string]$Server = '',
		[ValidateSet('account', 'share', 'share-legacy')][string]$Kind = 'share',
		[string]$User = '',
		[string]$Token = '',
		[string]$SubPath = '',
		[string]$Drive = '',
		[string]$Label = '',
		[bool]$ExplicitPort = $true,
		[bool]$Enabled = $true
	)
	if ([string]::IsNullOrWhiteSpace($Id)) { $Id = [guid]::NewGuid().ToString('N') }
	return [pscustomobject]@{
		Id = $Id; Server = $Server; Kind = $Kind; User = $User; Token = $Token
		SubPath = $SubPath; Drive = $Drive; Label = $Label
		ExplicitPort = $ExplicitPort; Enabled = $Enabled
	}
}