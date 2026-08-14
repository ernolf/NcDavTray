# OCS folder-tree call (NO &format = json; path is encoded or empty)
# Backward-compatible wrapper: returns parsed JSON only (or $null on error).
function Invoke-NcOcsFolderTree {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$User, [Parameter(Mandatory)][string]$Pass, [string]$EncodedPath, [int]$Depth = 1 )
	$res = Invoke-NcOcsFolderTreeRaw -Server $Server -User $User -Pass $Pass -EncodedPath $EncodedPath -Depth $Depth
	if ($res) { return $res.Json }
	return $null
}
