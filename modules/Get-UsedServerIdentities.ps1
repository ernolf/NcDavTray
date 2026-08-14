# Which of the two server identities Windows offers for a host are already taken.
# The answer cannot come from the configuration: the account mapping belongs to
# another process, and a connection made outside this product counts just the
# same. What Windows itself has on record is the only complete picture.
function Get-UsedServerIdentities {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server )
	$used = @{ Plain = $false; ExplicitPort = $false; Drives = @() }
	if ([string]::IsNullOrWhiteSpace($Server)) { return $used }
	$plain = '\\{0}@ssl\' -f $Server
	$port = '\\{0}@ssl@443\' -f $Server
	# Both sources are asked because neither is complete on its own:
	# Win32_NetworkConnection was seen to leave out a mapped drive that net use
	# lists, and Win32_LogicalDisk only knows connections that were given a letter,
	# while one made without a letter takes the identity just the same.
	$conns = @()
	try { foreach ($disk in @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=4' -ErrorAction Stop)) { $conns += [pscustomobject]@{ Remote = [string]$disk.ProviderName; Drive = [string]$disk.DeviceID } } } catch {}
	try { foreach ($conn in @(Get-CimInstance -ClassName Win32_NetworkConnection -ErrorAction Stop)) { $conns += [pscustomobject]@{ Remote = [string]$conn.RemoteName; Drive = [string]$conn.LocalName } } } catch {}
	$letters = @{}
	foreach ($c in $conns) {
		$hit = $false
		if ($c.Remote.StartsWith($port, [System.StringComparison]::OrdinalIgnoreCase)) { $used.ExplicitPort = $true; $hit = $true }
		elseif ($c.Remote.StartsWith($plain, [System.StringComparison]::OrdinalIgnoreCase)) { $used.Plain = $true; $hit = $true }
		# A connection made without a drive letter holds the identity just the same,
		# but there is nothing to name it by, so it counts without being listed.
		if ($hit -and ($c.Drive -match '^[A-Za-z]:$')) { $letters[$c.Drive.ToUpperInvariant()] = $true }
	}
	$used.Drives = @($letters.Keys | Sort-Object)
	return $used
}
