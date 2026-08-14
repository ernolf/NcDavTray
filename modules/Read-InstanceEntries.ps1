# A missing, empty or damaged list is not an error: it means nothing is running
# yet, or an instance died mid-write. Every reader has to cope with that anyway,
# so all three cases answer with an empty array.
function Read-InstanceEntries {
	$path = Get-InstanceListPath
	if (-not (Test-Path -LiteralPath $path)) { Write-Verbose "[Instances] Read-InstanceEntries: list not found"; return @() }
	try {
		$raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
		if (-not $raw) { Write-Verbose "[Instances] Read-InstanceEntries: list is empty"; return @() }
		$data = $raw | ConvertFrom-Json -ErrorAction Stop
		if ($null -eq $data) { Write-Verbose "[Instances] Read-InstanceEntries: json is null"; return @() }
		$result = @($data)
		Write-Verbose ("[Instances] Read-InstanceEntries: read {0} entries" -f $result.Count)
		return $result
	} catch { Write-Verbose ("[Instances] Read-InstanceEntries: ERROR {0}" -f $_.Exception.Message); return @() }
}
