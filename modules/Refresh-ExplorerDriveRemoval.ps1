function Refresh-ExplorerDriveRemoval([string]$drive) {
	# Notify Explorer about drive removal (force immediate refresh)
	try {
		$path = if ($drive -match '^[A-Za-z]:$') { "$drive\" } else { $drive }
		$flags = 0x0005 -bor 0x2000 # SHCNF_PATHW | SHCNF_FLUSHNOW
		# 1) Drive removed
		[Nc.Shell]::SHChangeNotify(0x00008000, $flags, $path, $null) # SHCNE_DRIVEREMOVED
		# 2) Network share gone (mapped WebDAV behaves like a net resource)
		[Nc.Shell]::SHChangeNotify(0x00002000, $flags, $path, $null) # SHCNE_NETUNSHARE
		# 3) Associations/images changed (final nudge)
		[Nc.Shell]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero) # SHCNE_ASSOCCHANGED
		# Give the shell a tick to process the queue
		[System.Windows.Forms.Application]::DoEvents()
		Start-Sleep -Milliseconds 150
	} catch {}
}
