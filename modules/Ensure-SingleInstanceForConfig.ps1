# Ensure single-instance per config.json (stores mutex in $script:cfgMutex)
function Ensure-SingleInstanceForConfig {
	# Use Global\ so different sessions/desktops collide properly. Use GetFullPath (file may not exist yet)
	$cfgPath = [System.IO.Path]::GetFullPath($PortJson).ToLowerInvariant()
	$key = 'Global\{0}_cfg_{1}' -f $AppName, (Get-Sha1Hex $cfgPath)
	$mutexVar = $null
	if (-not (Acquire-NamedMutex -Name $key -MutexOut ([ref]$mutexVar))) { Show-WarnT 'message.config_already_running' @{ path = $cfgPath }; exit 2 }
	$script:cfgMutex = $mutexVar
}
