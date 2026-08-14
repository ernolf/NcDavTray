function Fetch-ServerFavicon([string]$server) {
	# Downloads the raw .ico (multi-size) and persists it; also provides a Bitmap for UI preview.
	if ([string]::IsNullOrWhiteSpace($server)) { return $null }
	$url = "https://$server/index.php/apps/theming/favicon/core"
	$icoPath = Get-FavIconFilePath $server
	try {
		$req = New-HttpGetRequest $url 3000 'image/x-icon, image/*'
		$resp = $req.GetResponse()
		try {
			$ms = New-Object System.IO.MemoryStream
			try {
				$resp.GetResponseStream().CopyTo($ms)
				$bytes = $ms.ToArray()
				# ICO file magic: 00 00 01 00
				$isIco = ($bytes.Length -ge 4 -and $bytes[0] -eq 0 -and $bytes[1] -eq 0 -and $bytes[2] -eq 1 -and $bytes[3] -eq 0)
				# Persist original ICO for Explorer drive branding
				$dir = [System.IO.Path]::GetDirectoryName($icoPath)
				if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
				if ($isIco) {
					[System.IO.File]::WriteAllBytes($icoPath, $bytes)
					# Build a Bitmap for UI preview (PictureBox) from the saved .ico
					$fs = [System.IO.File]::OpenRead($icoPath)
					try { $ico = New-Object System.Drawing.Icon($fs); $bmp = $ico.ToBitmap(); $ico.Dispose() } finally { $fs.Dispose() }
					if ($script:ServerFaviconBmp) { try { $script:ServerFaviconBmp.Dispose() } catch {} }
					$script:ServerFaviconBmp = $bmp
					return $bmp
				} else {
					# Fallback: interpret as an image stream and convert to bitmap (single size)
					$ms.Position = 0
					$img = [System.Drawing.Image]::FromStream($ms)
					$bmp = New-Object System.Drawing.Bitmap $img
					$img.Dispose()
					if ($script:ServerFaviconBmp) { try { $script:ServerFaviconBmp.Dispose() } catch {} }
					$script:ServerFaviconBmp = $bmp
					# Also save a single-size .ico (better than nothing)
					try { Save-IconFromBitmap $bmp $icoPath | Out-Null } catch {}
					return $bmp
				}
			} finally { $ms.Dispose() }
		} finally { $resp.Close() }
	} catch { return $null }
}
