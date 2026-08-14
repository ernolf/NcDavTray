function New-StatusIcon {
	[CmdletBinding()]
	param(
		[Parameter(Position = 0)][string]$label,
		[Parameter(Position = 1)][System.Drawing.Color]$color,
		# circle for an account mount, rounded square for a public share
		[ValidateSet('circle', 'rounded')][string]$Shape = 'circle',
		# padlock overlay for a share the server wants a password for
		[switch]$Locked,
		# edge length in pixels; 0 asks the shell what it wants
		[int]$Size = 0
	)
	# The notification area asks for icons in SmallIconSize -- 16 px at 100 % scaling,
	# 20 at 125 %, 32 at 200 %. An icon built from one bitmap carries exactly that one
	# size, so any other is scaled by the shell, and a small icon has no detail to
	# spare. Drawing at the size that will be asked for is the whole point.
	if ($Size -le 0) { try { $Size = [System.Windows.Forms.SystemInformation]::SmallIconSize.Width } catch { $Size = 20 } }
	if ($Size -lt 16) { $Size = 16 }
	# Every measurement below is written in the 20 px scale the icon was designed in,
	# so at 20 this renders exactly as it did before the size became a parameter.
	[single]$k = $Size / 20.0
	$bmp = New-Object System.Drawing.Bitmap $Size, $Size
	$g = [System.Drawing.Graphics]::FromImage($bmp); $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'Half'; $g.TextRenderingHint = 'AntiAliasGridFit'; $g.Clear([System.Drawing.Color]::Transparent)
	$brush = New-Object System.Drawing.SolidBrush($color)
	if ($Shape -eq 'rounded') {
		[single]$d = 9 * $k # corner diameter
		$path = New-Object System.Drawing.Drawing2D.GraphicsPath
		$path.AddArc([single]0, [single]0, $d, $d, 180, 90)
		$path.AddArc([single]($Size - $d), [single]0, $d, $d, 270, 90)
		$path.AddArc([single]($Size - $d), [single]($Size - $d), $d, $d, 0, 90)
		$path.AddArc([single]0, [single]($Size - $d), $d, $d, 90, 90)
		$path.CloseFigure()
		$g.FillPath($brush, $path)
		$path.Dispose()
	} else {
		$g.FillEllipse($brush, [single]0, [single]0, [single]$Size, [single]$Size)
	}
	# up to 2 chars (e.g. "Z:")
	$txt = if ([string]::IsNullOrWhiteSpace($label)) { '!' } else { $label.Trim().ToUpper() }
	if ($txt.Length -gt 2) { $txt = $txt.Substring(0, 2) }
	# In pixels rather than points: the glyph has to grow with the bitmap, and a point
	# size is tied to the device resolution instead. 8 pt at 96 dpi is 10.667 px,
	# which is what the 20 px square was drawn with.
	$font = New-Object System.Drawing.Font($UiFontFamily, [single](10.667 * $k), $UiFontStyleBold, [System.Drawing.GraphicsUnit]::Pixel)
	$sf = New-Object System.Drawing.StringFormat; $sf.Alignment = 'Center'; $sf.LineAlignment = 'Center'; $sf.FormatFlags = $sf.FormatFlags -bor [System.Drawing.StringFormatFlags]::NoWrap; $sf.Trimming = [System.Drawing.StringTrimming]::None
	[single]$offsetY = 6 * $k; [single]$offsetX = $k * $(if ($txt.Length -eq 2) { 4 } else { 3 }); [single]$height = [Math]::Max(1, 16 * $k - $offsetY)
	$rect = New-Object System.Drawing.RectangleF([single]$offsetX, [single]$offsetY, [single](16 * $k), [single]$height)
	$g.DrawString($txt, $font, [System.Drawing.Brushes]::White, $rect, $sf)
	# The padlock rides on its own dark disc rather than directly on the icon: the
	# body underneath changes colour with the connection state, and a glyph that had
	# to stay legible on red and on green would be legible on neither.
	if ($Locked) {
		$badge = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(235, 30, 30, 30))
		$g.FillEllipse($badge, [single](9 * $k), [single](9 * $k), [single](11 * $k), [single](11 * $k))
		$shackle = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [single](1.35 * $k))
		$g.DrawArc($shackle, [single](13.7 * $k), [single](12.3 * $k), [single](3.4 * $k), [single](4.2 * $k), 180, 180)
		$g.FillRectangle([System.Drawing.Brushes]::White, [single](12.9 * $k), [single](14.7 * $k), [single](5 * $k), [single](3.7 * $k))
		$shackle.Dispose(); $badge.Dispose()
	}
	# Create HICON, clone the Icon to detach from the HICON, then destroy HICON
	$icon = $null; $hicon = [IntPtr]::Zero
	try { $hicon = $bmp.GetHicon(); $icoTmp = [System.Drawing.Icon]::FromHandle($hicon); $icon = [System.Drawing.Icon]$icoTmp.Clone(); $icoTmp.Dispose() }
	finally { if ($hicon -ne [IntPtr]::Zero) { [void][Nc.Win32]::DestroyIcon($hicon) }; $g.Dispose(); $brush.Dispose(); $font.Dispose(); $sf.Dispose(); $bmp.Dispose() }
	return $icon
}
