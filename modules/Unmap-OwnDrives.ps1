# Every configured mount comes off. They are only unmapped here, not disabled:
# the WebClient service being off is a condition to wait out, and the mounts are
# meant to come back once it runs again.
function Unmap-OwnDrives {
	Unmap-AllMounts
	try { Update-Trays } catch {}
}
