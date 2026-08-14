function Save-IconFromBitmap([System.Drawing.Bitmap]$bmp, [string]$icoPath) {
	if (-not $bmp -or [string]::IsNullOrWhiteSpace($icoPath)) { return $false }
	try {
		$hicon = $bmp.GetHicon(); $icoTmp = [System.Drawing.Icon]::FromHandle($hicon)
		try { $fs = [System.IO.File]::Open($icoPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read); try { $icoTmp.Save($fs) } finally { $fs.Close() } }
		# Dispose wrapper and destroy HICON to avoid leaks
		finally { $icoTmp.Dispose(); if ($hicon -ne [IntPtr]::Zero) { [void][Nc.Win32]::DestroyIcon($hicon) } }
		return $true
	} catch { return $false }
}
