# Puts every tooltip that is on screen into the language now in force. The menus
# need nothing: each one writes its labels when it opens. A tooltip is already up,
# and left alone it would keep the old language until the next poll happened to
# overwrite it -- a whole check interval of reading as if the switch had not taken.
# What each one says comes from the state the tray recorded, not from asking the
# drives again: this is a relabelling, not a refresh.
function Update-TrayTips {
	[CmdletBinding()] param()
	$tip = if ($script:ServiceDeactivated) { T 'tray.service_deactivated' @{ app = $AppName } } else { T 'tray.manager' @{ app = $AppName } }
	try { if ($script:TrayManager) { Set-TrayTipText $script:TrayManager.Notify $tip } } catch {}
	foreach ($entry in @($State.Mounts)) {
		if (-not $entry -or -not $script:Trays.ContainsKey($entry.Id)) { continue }
		$rec = $script:Trays[$entry.Id]
		try { Set-TrayTipText $rec.Notify (Get-MountTrayText $entry $rec.Status $rec.Rc) } catch {}
	}
}