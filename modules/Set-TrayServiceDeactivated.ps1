# Says on the application icon that the WebClient service is off. The mount
# icons are left alone: the next poll takes them down anyway, and there is no
# drive left for them to describe.
function Set-TrayServiceDeactivated {
	try { if ($script:TrayManager) { Set-TrayTipText $script:TrayManager.Notify (T 'tray.service_deactivated' @{ app = $AppName }) } } catch {}
}
