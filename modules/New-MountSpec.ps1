# Describes one mapping target. Everything the mapping functions need to know
# about a mount travels in this object, so none of them has to reach into a
# global state:
#   Kind = 'account'       /remote.php/dav/files/<User>, login <User>
#   Kind = 'share'         /public.php/dav/files/<Token>, login 'anonymous'
#   Kind = 'share-legacy'  /public.php/webdav, login <Token> (pre-NC29 servers,
#                          and for now every password protected share, see
#                          Ensure-MountPassword)
# ExplicitPort appends '@443' to the host part. The mini-redirector keys its
# sessions on the host string, so the explicit port forms a second server
# identity for the same host and lets a share coexist with an account mapping
# instead of failing with ERROR_SESSION_CREDENTIAL_CONFLICT (1219).
function New-MountSpec {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server, [ValidateSet('account', 'share', 'share-legacy')][string]$Kind = 'account', [string]$User = '', [string]$Token = '', [string]$SubPath = '', [string]$Drive = '', [string]$Label = '', [switch]$ExplicitPort )
	return [pscustomobject]@{
		Server = $Server; Kind = $Kind; User = $User; Token = $Token
		SubPath = $SubPath; Drive = $Drive; Label = $Label
		ExplicitPort = [bool]$ExplicitPort
	}
}
