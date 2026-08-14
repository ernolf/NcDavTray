function Test-DriveMatchesDesired {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	try {
		$ident = Get-MountIdentity $Spec
		if (-not (Test-ValidDrive $Spec.Drive) -or [string]::IsNullOrWhiteSpace($Spec.Server) -or [string]::IsNullOrWhiteSpace($ident)) { return $false }
		$pd = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { ('{0}:' -f $_.Name) -ieq $Spec.Drive } | Select-Object -First 1
		if (-not $pd) { return $false }
		$root = if ($pd.PSObject.Properties.Name -contains 'DisplayRoot' -and $pd.DisplayRoot) { $pd.DisplayRoot } else { $pd.Root }
		if (-not $root) { return $false }
		# Accept both UNC shapes, with optional trailing backslash:
		# \\<host>\<endpoint>\<subpath>
		# \\<host>\DavWWWRoot\<endpoint>\<subpath>
		$hostRx = [regex]::Escape((Get-MountHostPart $Spec))
		$pathRx = ((Get-MountPathSegments $Spec) | ForEach-Object { [regex]::Escape($_) }) -join '\\'
		$rx = '^\\\\' + $hostRx + '\\(?:DavWWWRoot\\)?' + $pathRx + '(?:\\)?$'
		return ($root -imatch $rx)
	} catch { return $false }
}
