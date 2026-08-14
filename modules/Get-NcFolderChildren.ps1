# depth = 1 listing of children folder names at given parent path
function Get-NcFolderChildren {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)][AllowEmptyString()][string]$Server,
		[Parameter(Mandatory)][AllowEmptyString()][string]$User,
		[Parameter(Mandatory)][AllowEmptyString()][string]$Pass,
		[AllowEmptyString()][string]$ParentPath
	)
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return @() }
	if ([string]::IsNullOrWhiteSpace($Pass)) { return @() }
	$enc = Encode-OcsPath $ParentPath
	$res = Invoke-NcOcsFolderTree -Server $Server -User $User -Pass $Pass -EncodedPath $enc -Depth 1
	if ($null -eq $res) { return @() }
	# Expect array of objects with 'basename'
	if ($res -is [System.Array]) { return ($res | Where-Object { $_.PSObject.Properties.Name -contains 'basename' } | ForEach-Object { [string]$_.basename }) | Sort-Object }
	if ($res.PSObject.Properties.Name -contains 'ocs' -and ($res.ocs.data -is [System.Array])) { return ($res.ocs.data | Where-Object { $_.PSObject.Properties.Name -contains 'basename' } | ForEach-Object { [string]$_.basename }) | Sort-Object }
	return @()
}
