# A server string is the host and, when the instance runs in a subdirectory, the
# path it is installed under: 'cloud.example.com/nextcloud'. Both halves travel
# in the one field the user types them into, because they are one address.
# A URL needs it whole and every https:// call builds it that way. Windows needs
# the host alone: the redirector keys its session on that string, and an
# installation path in it would not be a host any more.
# Key is what a lookup is filed under -- the host folded to lower case, the
# installation path left alone. DNS makes no distinction between 'Cloud' and
# 'cloud', a directory on the server does.
function Split-ServerString {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server )
	$s = ([string]$Server).Trim().Trim('/')
	$i = $s.IndexOf('/')
	$h = if ($i -lt 0) { $s } else { $s.Substring(0, $i) }
	$b = if ($i -lt 0) { '' } else { $s.Substring($i + 1).Trim('/') }
	$key = if ($b) { '{0}/{1}' -f $h.ToLowerInvariant(), $b } else { $h.ToLowerInvariant() }
	return @{ Host = $h; BasePath = $b; Key = $key }
}
