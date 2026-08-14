# Takes every configured mount off its drive letter and nothing else. The tray
# icons are deliberately left alone: this also runs in the watchdog process,
# where there are none and where building them would put a second set of icons
# on the screen.
function Unmap-AllMounts {
	foreach ($entry in @($State.Mounts)) {
		if (-not $entry) { continue }
		try { Unmap-DriveIfOurs -Spec (New-MountSpecFromEntry $entry) -Force -RemoveProfile } catch {}
	}
}
