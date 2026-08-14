# Shows a small custom balloon near the mouse cursor (no dependencies).
function Show-CustomBalloon([string]$Title, [string]$Text, [int]$TimeoutMs = 2200) {
	Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing
	# --- normalize inputs to strings (avoid Object[] math) ---
	if ($Title -is [array]) { $Title = ($Title -join ' ') }; if ($Text -is [array]) { $Text = ($Text -join "`n") }
	# close any previous balloon
	try {
		if ($script:BalloonTimer) { $script:BalloonTimer.Stop(); $script:BalloonTimer.Dispose(); $script:BalloonTimer = $null }
		if ($script:BalloonForm -and -not $script:BalloonForm.IsDisposed) { $script:BalloonForm.Close(); $script:BalloonForm.Dispose() }
	} catch {}
	[System.Drawing.Image]$IconImage = Get-EmbeddedImage -Base64 $Logo96B64
	$script:BalloonForm = $null
	# --- layout (larger) ---
	$pad = 12; $iconSz = 96; $gap = 8
	$fontTitle = New-Object System.Drawing.Font($UiFontFamily, 12, $UiFontStyleBold); $fontText = New-Object System.Drawing.Font($UiFontFamily, 8, $UiFontStyleBold) #[System.Drawing.FontStyle]::Regular)
	$fmt = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor [System.Windows.Forms.TextFormatFlags]::NoPadding
	$maxTextWidth = 520
	# Measure using TextRenderer (more faithful to WinForms than Graphics.MeasureString)
	$szTitle = [System.Windows.Forms.TextRenderer]::MeasureText($Title, $fontTitle)
	$szText = [System.Windows.Forms.TextRenderer]::MeasureText($Text, $fontText, (New-Object System.Drawing.Size($maxTextWidth, 9999)), $fmt)
	$wText = [Math]::Max($szTitle.Width, $szText.Width); $wIcon = if ($IconImage) { $iconSz + $pad } else { 0 }
	$w = [int]($pad + $wIcon + $wText + $pad); $h = [int]($pad + [Math]::Max($iconSz, $szTitle.Height + $gap + $szText.Height) + $pad)
	# enforce bigger popup footprint when icon is large
	if ($w -lt ( $pad + $iconSz + 160 )) { $w = $pad + $iconSz + 160 }; if ($h -lt ( $pad + $iconSz + $pad )) { $h = $pad + $iconSz + $pad }
	# --- form ---
	$f = New-Object System.Windows.Forms.Form; $f.FormBorderStyle = 'None'; $f.StartPosition = 'Manual'; $f.TopMost = $true; $f.ShowInTaskbar = $false; $f.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 250); $f.Size = New-Object System.Drawing.Size($w, $h)
	# allow ESC to close the balloon
	$f.KeyPreview = $true
	$f.Add_KeyDown(({ param($s, $e) if ($e.KeyCode -eq 'Escape') { try { $myForm.Close() } catch {} } }).GetNewClosure())
	# Rounded region (safe: keep path in Tag so it's alive during Paint)
	$path = New-Object System.Drawing.Drawing2D.GraphicsPath; $radius = 10; $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
	$path.AddArc(0, 0, $radius, $radius, 180, 90); $path.AddArc($w-$radius, 0, $radius, $radius, 270, 90); $path.AddArc($w-$radius, $h-$radius, $radius, $radius, 0, 90); $path.AddArc(0, $h-$radius, $radius, $radius, 90, 90); $path.CloseFigure()
	$f.Region = New-Object System.Drawing.Region($path)
	# Keep resources on form to avoid GC while painting
	$f.Tag = @{ Path = $path; FontTitle = $fontTitle; FontText = $fontText; IconImage = $IconImage; Padding = $pad; IconSz = $iconSz; Gap = $gap; Title = $Title; Text = $Text; Fmt = $fmt }
	# Paint
	$f.Add_Paint({
		param($s, $e)
		$g = $e.Graphics; $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
		$t = $s.Tag; if (-not $t) { return }
		# hard-cast everything used in arithmetic to int
		$wClient = [int]$s.ClientSize.Width; $hClient = [int]$s.ClientSize.Height
		$pad = [int]$t.Padding; $iconSz = [int]$t.IconSz; $gap = [int]$t.Gap; $x = [int]$pad; $y = [int]$pad
		# soft border shadow
		$shadow = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(40, 0, 0, 0), 1)
		if ($t.Path -and $t.Path.PointCount -gt 0) { $g.DrawPath($shadow, $t.Path) }
		$shadow.Dispose()
		$x = $t.Padding; $y = $t.Padding
		if ($t.IconImage) { try { $g.DrawImage($t.IconImage, $x, $y, $iconSz, $iconSz) } catch {}; $x = [int]($x + $iconSz + $pad) }
		[System.Windows.Forms.TextRenderer]::DrawText($g, $t.Title, $t.FontTitle, [System.Drawing.Point]::new($x, $y), [System.Drawing.Color]::Black)
		$y = [int]($y + [int][Math]::Ceiling($t.FontTitle.GetHeight($g)) + $gap)
		# Wrap text inside remaining width
		$remainW = [int]($wClient - $x - $pad)
		[System.Windows.Forms.TextRenderer]::DrawText( $g, $t.Text, $t.FontText, (New-Object System.Drawing.Rectangle($x, [int]$y, [int]$remainW, $s.ClientSize.Height)), [System.Drawing.Color]::DimGray, $t.Fmt )
		# tiny 'Click to close' hint
		$hint = 'Click to close'; $hintFont = New-Object System.Drawing.Font($UiFontFamily, 7, [System.Drawing.FontStyle]::Regular)
		$szHint = [System.Windows.Forms.TextRenderer]::MeasureText($hint, $hintFont)
		$hx = [int]($wClient - $pad - [int]$szHint.Width); $hy = [int]($hClient - $pad - [int]$szHint.Height)
		[System.Windows.Forms.TextRenderer]::DrawText($g, $hint, $hintFont, (New-Object System.Drawing.Point($hx, $hy)), [System.Drawing.Color]::Gray)
		$hintFont.Dispose()
	})
	# Balloon as Chrome-Style Toast:
	$screen = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
	$posX = $screen.Right - $w - 10; $posY = $screen.Bottom - $h - 10
	$f.Location = New-Object System.Drawing.Point($posX, $posY); $f.Location = New-Object System.Drawing.Point($posX, $posY)
	# Close on click / mousedown / ESC (sender-based, no $myForm, no GetNewClosure)
	$f.Add_Click({ param($s, $e) try { $s.Close() } catch {} }); $f.Add_MouseDown({ param($s, $e) try { $s.Close() } catch {} }); $f.KeyPreview = $true; $f.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Escape') { try { $s.Close() } catch {} } })
	# Auto-close via WinForms timer (UI-thread; safe with message pump)
	$t = New-Object System.Windows.Forms.Timer; $t.Interval = [Math]::Max(500, $TimeoutMs)
	# freeze locals for this instance (avoid capturing $f/$t by reference)
	$myForm = $f; $myTimer = $t
	$t.Add_Tick(({ try { $myTimer.Stop(); $myTimer.Dispose() } catch {}; try { if ($myForm -and -not $myForm.IsDisposed) { $myForm.Close() } } catch {} }).GetNewClosure())
	$script:BalloonTimer = $t; $script:BalloonForm = $f
	# Dispose resources when form closes
	$f.Add_FormClosed(({
		try { if ($myTimer) { $myTimer.Stop(); $myTimer.Dispose() } } catch {}
		try { if ($myForm.Tag) { if ($myForm.Tag.Path) { $myForm.Tag.Path.Dispose(); $myForm.Tag.Path = $null }; if ($myForm.Tag.FontTitle) { $myForm.Tag.FontTitle.Dispose(); $myForm.Tag.FontTitle = $null }; if ($myForm.Tag.FontText) { $myForm.Tag.FontText.Dispose(); $myForm.Tag.FontText = $null }; if ($myForm.Tag.IconImage) { $myForm.Tag.IconImage.Dispose(); $myForm.Tag.IconImage = $null } } } catch {}
		try { $myForm.Dispose() } catch {}
		# reset globals only if they still point to THIS instance
		try { if ($script:BalloonForm -eq $myForm) { $script:BalloonForm = $null }; if ($script:BalloonTimer -eq $myTimer) { $script:BalloonTimer = $null } } catch {}
	}).GetNewClosure())
	try { $t.Start() } catch {}; $f.Add_Shown({ param($s, $e); try { $s.Invalidate() } catch {} }); $f.Show(); try { $f.Activate(); $f.BringToFront(); [void]$f.Focus() } catch {}
}
