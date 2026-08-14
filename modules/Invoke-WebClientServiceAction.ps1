# Elevate and start/restart the WebClient service
function Invoke-WebClientServiceAction([ValidateSet('start', 'restart')][string]$Action, [switch]$NoWait) {
	$cmd = if ($Action -eq 'restart') {
		"try { Stop-Service WebClient -ErrorAction SilentlyContinue; Start-Service WebClient -ErrorAction Stop; exit 0 } catch { exit 1 }"
	} else {
		"try { Start-Service WebClient -ErrorAction Stop; exit 0 } catch { exit 1 }"
	}
	$pwsh = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
	if (-not (Test-Path $pwsh)) { $pwsh = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe' }
	$psi = New-Object System.Diagnostics.ProcessStartInfo
	$psi.FileName = $pwsh; $psi.Arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$cmd`""
	$psi.Verb = 'runas'; $psi.UseShellExecute = $true; $psi.WindowStyle = 'Hidden'; $psi.CreateNoWindow = $true
	try { $p = [Diagnostics.Process]::Start($psi); if ($NoWait) { return $true }; $p.WaitForExit(); return ($p.ExitCode -eq 0) } catch { return $false }
}
