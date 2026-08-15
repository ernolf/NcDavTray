# depth = 0 strict existence check via RAW call:
# - $true = > exists OR unknown (offline/auth/maintenance/other errors)
# - $false = > ONLY when HTTP 404 AND exact JSON { "message": "Folder not found" }
# The account to ask is handed in rather than read from anywhere: the settings page
# asks about the account it is editing, which is not necessarily the one the
# running program is mapping.
function Test-NcFolderExists {
	[CmdletBinding()] param( [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [Parameter(Mandatory)][AllowEmptyString()][string]$User, [Parameter(Mandatory)][AllowEmptyString()][string]$Pass, [AllowEmptyString()][string]$SubPath )
	if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($User)) { return $true }
	if ([string]::IsNullOrWhiteSpace($Pass)) { return $true }
	$enc = Encode-OcsPath $SubPath
	$res = Invoke-NcOcsFolderTreeRaw -Server $Server -User $User -Pass $Pass -EncodedPath $enc -Depth 0
	if ($res -and $res.StatusCode -eq 200) { return $true }
	if ($res -and $res.StatusCode -eq 404) {
		if ($res.Json -and ($res.Json.PSObject.Properties.Name -contains 'message')) { if ([string]$res.Json.message -eq 'Folder not found') { return $false } }
		return $true # 404 but no exact "Folder not found" -> treat as unknown (NOT false)
	}
	return $true # Any other status or error -> unknown (NOT false)
}
