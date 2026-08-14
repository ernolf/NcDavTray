# Every installed main instance in this session, this process excluded. What
# identifies them is the command line: it carries the path of the installed
# script. The watchdog carries it too, which is why it is filtered out here -- it
# goes down with the copy it guards, not before it.
function Get-RunningInstalledMain {
	[CmdletBinding()] param()
	if (-not (Test-Path -LiteralPath $InstallBin)) { return @() }
	try {
		$esc = [regex]::Escape($InstallBin)
		$mySession = (Get-Process -Id $PID).SessionId
		$procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
			$_.SessionId -eq $mySession -and $null -ne $_.CommandLine -and $_.CommandLine -match $esc -and $_.CommandLine -notmatch '-Watchdog'
		}
		$out = @()
		foreach ($p in @($procs)) {
			try { $dp = Get-Process -Id $p.ProcessId -ErrorAction Stop; if ($dp.Id -ne $PID) { $out += $dp } } catch {}
		}
		return $out
	} catch { return @() }
}