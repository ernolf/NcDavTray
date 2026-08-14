function Get-WebClientTriggerInfoText {
	[CmdletBinding()] param([string]$ServiceName = 'WebClient', [ValidateSet('String','Window')] [string]$Output = 'String')
	try { $scOutput = & sc.exe qtriggerinfo $ServiceName 2>$null } catch { return $null }
	if (-not $scOutput) { return $null }
	$match = $scOutput | Select-String -Pattern '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' -AllMatches | Select-Object -First 1
	if (-not $match -or -not $match.Matches.Count) { return $null }
	$uuid = $match.Matches[0].Value.ToLower()
	if (-not $uuid) { return $null }
	$name = $uuid
	try {
		$keyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{$uuid}"
		$val = (Get-Item $keyPath -ErrorAction Stop).GetValue('')
		if ($val) { $name = [string]$val }
	} catch {}
	if ($Output -eq 'Window') { Show-InfoT 'message.service_trigger_info' @{ name = $name; uuid = $uuid } } else { return "Trigger: $name ($uuid)" }
}
