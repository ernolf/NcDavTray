function New-WebDavMapSecure([string]$drive, [string]$unc, [string]$user, [string]$pass, [switch]$Persist, [ref]$LastError) {
	# Build NETRESOURCE
	$nr = New-Object Nc.NetUse+NETRESOURCE
	$nr.dwType = [Nc.NetUse]::RESOURCETYPE_DISK
	$nr.lpLocalName = $drive
	$nr.lpRemoteName = $unc
	$nr.lpComment = $null
	$nr.lpProvider = $null
	$flags = if ($Persist) { [Nc.NetUse]::CONNECT_UPDATE_PROFILE } else { 0 }
	$rc = [Nc.NetUse]::WNetAddConnection2([ref]$nr, $pass, $user, $flags)
	if ($PSBoundParameters.ContainsKey('LastError')) { $LastError.Value = $rc }
	return ($rc -eq 0)
}
