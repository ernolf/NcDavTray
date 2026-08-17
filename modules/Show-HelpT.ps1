# i18n: custom help dialog with optional clickable URL
# An optional second button leaves the dialog with DialogResult 'Retry', which is
# how a help window can offer the way its subject can be avoided altogether.
function global:Show-HelpT([string]$TitleKey, [hashtable]$TitleVars = $null, [string]$BodyKey, [hashtable]$BodyVars = $null, [string]$Url = $null, [int]$Width = 640, [int]$Height = 320, [System.Windows.Forms.Form]$Parent = $null, [string]$AltButtonKey = $null) {
	Add-Type -AssemblyName System.Windows.Forms
	Add-Type -AssemblyName System.Drawing
	# Resolve i18n
	$title = T $TitleKey $TitleVars; $body = T $BodyKey $BodyVars; $okTxt = T 'button.ok'
	# Form
	$f = New-Object System.Windows.Forms.Form; Apply-BrandIconToForm $f; Hook-FormDpi $f; Hook-FormScreen $f; $f.Text = $title; $f.StartPosition = $(if ($Parent) { 'CenterParent' } else { 'CenterScreen' }); $f.FormBorderStyle = 'FixedDialog'; $f.MinimizeBox = $false; $f.MaximizeBox = $false; $f.ShowInTaskbar = $false; $f.TopMost = $true; $f.AutoScaleMode = 'Dpi'; $f.Width = $Width; $f.Height = $Height; $wrapW = [Math]::Max(200, $f.ClientSize.Width - 32); $f.Font = New-Object System.Drawing.Font($UiFontFamily, 9)
	# DPI scale (96dpi = 1.0)
	$scale = ($f.DeviceDpi / 96.0); $icoPx = [int][Math]::Ceiling(32 * $scale) # target box size for the icon
	# Layout root
	$root = New-Object System.Windows.Forms.TableLayoutPanel; $root.Dock = 'Fill'; $root.Padding = New-Object System.Windows.Forms.Padding(12, 12, 12, 12); $root.ColumnCount = 1; $root.RowCount = $(if ($Url) { 4 } else { 3 })
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null
	if ($Url) { $root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::AutoSize))) | Out-Null }
	$btnRowHeight = $script:ButtonXH + (2 * $script:ButtonPadY)
	$root.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $btnRowHeight))) | Out-Null
	# Header (Help icon + title label)
	$hdr = New-Object System.Windows.Forms.FlowLayoutPanel
	$hdr.AutoSize = $true
	$hdr.FlowDirection = 'LeftToRight'
	$hdr.WrapContents = $false
	$pic = New-Object System.Windows.Forms.PictureBox
	$pic.SizeMode = 'Zoom' # 'CenterImage' # 'Zoom' to avoid cropping
	$pic.Width = $icoPx; $pic.Height = $icoPx
	$pic.Margin = New-Object System.Windows.Forms.Padding(0, 2, 8, 0) # a bit of breathing room
	$pic.Image = [System.Drawing.SystemIcons]::Information.ToBitmap()
	$lblTitle = New-Object System.Windows.Forms.Label; $lblTitle.AutoSize = $true; $lblTitle.Font = New-Object System.Drawing.Font($f.Font.FontFamily, ($f.Font.Size + 2), $UiFontStyleBold); $lblTitle.Text = $title; $lblTitle.Margin = New-Object System.Windows.Forms.Padding(8, 6, 0, 0)
	# Wraps like the body does: a heading that fits in one language runs past the
	# window in the next.
	$lblTitle.MaximumSize = New-Object System.Drawing.Size(([Math]::Max(200, $wrapW - $icoPx - 16)), 0)
	$hdr.Controls.AddRange(@($pic, $lblTitle))
	# Body
	$lblBody = New-Object System.Windows.Forms.Label; $lblBody.AutoSize = $true; $lblBody.MaximumSize = New-Object System.Drawing.Size($wrapW, 0); $lblBody.Text = $body; $lblBody.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0); $lblBody.UseMnemonic = $false
	# Optional URL + Copy
	$urlPanel = $null
	if ($Url) {
		$urlPanel = New-Object System.Windows.Forms.FlowLayoutPanel; $urlPanel.AutoSize = $true; $urlPanel.FlowDirection = 'LeftToRight'; $urlPanel.WrapContents = $false; $urlPanel.Margin = New-Object System.Windows.Forms.Padding(0, 8, 0, 0)
		$lnk = New-Object System.Windows.Forms.LinkLabel; $lnk.Text = $Url; $lnk.AutoSize = $true
		$lnk.add_LinkClicked({ param($s, $e); try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $Url; $psi.UseShellExecute = $true; [System.Diagnostics.Process]::Start($psi) | Out-Null } catch {} })
		$btnCopy = New-Object System.Windows.Forms.Button; $btnCopy.Text = T 'button.copy_url'
		$btnCopy.AutoSize = $true; $btnCopy.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly; $btnCopy.Height = $script:ButtonH; $btnCopy.Margin = New-Object System.Windows.Forms.Padding(8, $script:ButtonCopyOffsetY, 0, 0)
		$btnCopy.Add_Click({ try { [System.Windows.Forms.Clipboard]::SetText($Url) } catch {} })
		$urlPanel.Controls.AddRange(@($lnk, $btnCopy))
	}
	# Buttons (OK right aligned)
	$btnRow = New-Object System.Windows.Forms.FlowLayoutPanel; $btnRow.Dock = 'Bottom' <# 'Fill' #>; $btnRow.FlowDirection = 'RightToLeft'; $btnRow.AutoSize = $false; $btnRow.Height = $script:ButtonXH + (2 * $script:ButtonPadY); $btnRow.Padding = New-Object System.Windows.Forms.Padding(0, $script:ButtonPadY, 0, 0)
	$ok = New-Object System.Windows.Forms.Button; $ok.Text = $okTxt; $ok.Width = $script:ButtonMinW; $ok.Height = $script:ButtonXH; $ok.Add_Click({ $f.Close() })
	$btnRow.Controls.Add($ok)
	if (-not [string]::IsNullOrWhiteSpace($AltButtonKey)) {
		$alt = New-Object System.Windows.Forms.Button; $alt.Text = (T $AltButtonKey); $alt.AutoSize = $true; $alt.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowOnly; $alt.Height = $script:ButtonXH; $alt.Margin = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
		$alt.Add_Click({ $f.DialogResult = [System.Windows.Forms.DialogResult]::Retry; $f.Close() })
		$btnRow.Controls.Add($alt)
	}
	$f.AcceptButton = $ok
	$f.CancelButton = $ok
	# ESC to close
	$f.KeyPreview = $true
	$f.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'Escape') { try { $s.Close() } catch {} } })
	# Compose
	$root.Controls.Add($hdr)
	$root.Controls.Add($lblBody)
	if ($urlPanel) { $root.Controls.Add($urlPanel) }
	$root.Controls.Add($btnRow)
	$f.Controls.Add($root)
	# The height the caller asked for is a minimum, not a measurement: the same
	# text runs several lines longer in some languages, and what does not fit
	# pushes the button row out of the window.
	$need = $root.GetPreferredSize((New-Object System.Drawing.Size($f.ClientSize.Width, 0))).Height + ($f.Height - $f.ClientSize.Height)
	if ($need -gt $f.Height) { $f.Height = $need }
	if ($Parent) { return $f.ShowDialog($Parent) } else { return $f.ShowDialog() }
}
