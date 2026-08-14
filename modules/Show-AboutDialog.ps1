# The About box. It carries the version, the author and the project link, none of
# which belongs to a single drive, so it is reached from the tray that stands for
# the whole installation rather than from a drive's menu.
function Show-AboutDialog {
	$f = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $f
	Hook-FormScreen $f
	Hook-FormDpi $f
	$f.Text = (T 'title.about' @{ app = $AppName }); $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true; $f.Width = 420; $f.Height = 220; $f.AutoScaleMode = 'Dpi'; $f.Font = New-Object System.Drawing.Font($UiFontFamily, 9)
	$lblTit = New-Object System.Windows.Forms.Label; $lblTit.Text = "ernolfs $AppName"; $lblTit.AutoSize = $true
	$lblTit.Font = New-Object System.Drawing.Font($UiFontFamily, 11, $UiFontStyleBold); $lblTit.Left = 16; $lblTit.Top = 16; $lblTit.UseCompatibleTextRendering = $false
	$lblDes = New-Object System.Windows.Forms.Label; $lblDes.Left = 16; $lblDes.Top = 44; $lblDes.Text = (T 'about.des'); $lblDes.AutoSize = $true; $lblDes.MaximumSize = New-Object System.Drawing.Size(260, 0) # <- slightly narrower to make room for avatar
	$lblVer = New-Object System.Windows.Forms.Label; $lblVer.Left = 16; $lblVer.Top = 88; $lblVer.Text = (T 'about.ver' @{ version = $Version }); $lblVer.AutoSize = $true
	$lblAut = New-Object System.Windows.Forms.Label; $lblAut.Left = 16; $lblAut.Top = 110; $lblAut.Text = (T 'about.aut' @{ author = $Author }); $lblAut.AutoSize = $true
	$link = New-Object System.Windows.Forms.LinkLabel; $link.Text = $ProjectUrl; $link.Left = 16; $link.Top = 132; $link.AutoSize = $true; $link.add_LinkClicked({ param($s, $e); try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $ProjectUrl; $psi.UseShellExecute = $true; [System.Diagnostics.Process]::Start($psi) | Out-Null } catch {} })
	$avatarImg = Get-EmbeddedImage -Base64 $ernolfB64 # Avatar on the right
	$pb = $null
	if ($avatarImg) { $pb = New-Object System.Windows.Forms.PictureBox; $pb.Width = 96; $pb.Height = 96; $pb.SizeMode = 'Zoom'; $pb.Image = $avatarImg; $pb.Left = $f.ClientSize.Width - $pb.Width - 16; $pb.Top = 16; $pb.Anchor = 'Top, Right' }
	$ok = New-Object System.Windows.Forms.Button; $ok.Text = (T 'button.ok'); $ok.Width = 80; $ok.Height = $script:ButtonXH; $ok.Left = $f.ClientSize.Width - $ok.Width - 16; $ok.Top = $f.ClientSize.Height - $ok.Height - 16; $ok.Anchor = 'Bottom, Right'; $ok.Add_Click({ $f.Close() })
	# Dispose avatar image to free GDI handles
	$f.add_FormClosed({ if ($pb -and $pb.Image) { try { $pb.Image.Dispose() } catch {} } })
	if ($pb) { $f.Controls.AddRange(@($lblTit, $lblDes, $lblVer, $lblAut, $link, $pb, $ok)) }
	else { $f.Controls.AddRange(@($lblTit, $lblDes, $lblVer, $lblAut, $link, $ok)) }
	[void]$f.ShowDialog()
}
