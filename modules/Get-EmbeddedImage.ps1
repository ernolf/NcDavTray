# Decode base64 -> Image -> Bitmap; optional: force 32bpp PArgb for safer UI drawing
function Get-EmbeddedImage([string]$Base64, [switch]$ForcePArgb) {
	if ([string]::IsNullOrWhiteSpace($Base64)) { return $null }
	try {
		$bytes = [Convert]::FromBase64String($Base64)
		$ms = New-Object System.IO.MemoryStream(, $bytes)
		$img = [System.Drawing.Image]::FromStream($ms)
		if ($ForcePArgb) {
			$bmp = New-Object System.Drawing.Bitmap -ArgumentList $img.Width, $img.Height, ([System.Drawing.Imaging.PixelFormat]::Format32bppPArgb)
			$g = [System.Drawing.Graphics]::FromImage($bmp); $g.DrawImage($img, 0, 0, $img.Width, $img.Height); $g.Dispose()
		} else { $bmp = New-Object System.Drawing.Bitmap $img }
		$img.Dispose(); $ms.Dispose()
		return $bmp
	} catch { return $null }
}
