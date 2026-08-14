# Whether the named program starts with Windows. A portable copy never does: it
# has no fixed place to start from.
function Is-StartupRunKeyEnabled([string]$Name = $AppName) {
	if ($PortableMode) { return $false }
	$val = Get-ItemProperty -Path $RunKey -Name $Name -ErrorAction SilentlyContinue
	return ($null -ne $val)
}