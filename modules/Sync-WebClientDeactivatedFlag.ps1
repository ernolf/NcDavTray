# Keeps script-level deactivated flag in sync with the current WebClient StartType
function Sync-WebClientDeactivatedFlag {
	param(
		[System.ServiceProcess.ServiceController]$Service
	)
	try {
		if (-not $Service) { $Service = Get-Service -Name WebClient -ErrorAction Stop }
		$startRaw = [string]$Service.StartType
		$script:ServiceDeactivated = ($startRaw -like 'Disabled*')
		return $Service
	} catch { $script:ServiceDeactivated = $true; return $null } # Missing or inaccessible service -> treat as deactivated
}
