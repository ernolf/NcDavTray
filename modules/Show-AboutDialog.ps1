# The About box. It carries the version, the author and the project link, none of
# which belongs to a single drive, so it is reached from the tray that stands for
# the whole installation rather than from a drive's menu. The version is also what
# an update is measured against, which is why the check sits here and nowhere else.
function Show-AboutDialog {
	$f = New-Object System.Windows.Forms.Form
	Apply-BrandIconToForm $f
	Hook-FormScreen $f
	Hook-FormDpi $f
	$f.Text = (T 'title.about' @{ app = $AppName }); $f.StartPosition = 'CenterScreen'; $f.FormBorderStyle = 'FixedDialog'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.TopMost = $true; $f.Width = 420; $f.Height = 320; $f.AutoScaleMode = 'Dpi'; $f.Font = New-Object System.Drawing.Font($UiFontFamily, 9)
	$lblTit = New-Object System.Windows.Forms.Label; $lblTit.Text = "ernolfs $AppName"; $lblTit.AutoSize = $true
	$lblTit.Font = New-Object System.Drawing.Font($UiFontFamily, 11, $UiFontStyleBold); $lblTit.Left = 16; $lblTit.Top = 16; $lblTit.UseCompatibleTextRendering = $false
	$lblDes = New-Object System.Windows.Forms.Label; $lblDes.Left = 16; $lblDes.Top = 44; $lblDes.Text = (T 'about.des'); $lblDes.AutoSize = $true; $lblDes.MaximumSize = New-Object System.Drawing.Size(260, 0) # <- slightly narrower to make room for avatar
	$lblVer = New-Object System.Windows.Forms.Label; $lblVer.Left = 16; $lblVer.Top = 88; $lblVer.Text = (T 'about.ver' @{ version = $Version }); $lblVer.AutoSize = $true
	$lblAut = New-Object System.Windows.Forms.Label; $lblAut.Left = 16; $lblAut.Top = 110; $lblAut.Text = (T 'about.aut' @{ author = $Author }); $lblAut.AutoSize = $true
	$link = New-Object System.Windows.Forms.LinkLabel; $link.Text = $ProjectUrl; $link.Left = 16; $link.Top = 132; $link.AutoSize = $true; $link.add_LinkClicked({ param($s, $e); try { $psi = New-Object System.Diagnostics.ProcessStartInfo; $psi.FileName = $ProjectUrl; $psi.UseShellExecute = $true; [System.Diagnostics.Process]::Start($psi) | Out-Null } catch {} })
	# The answer of the last check, and empty until there was one: a line that says
	# something about updates before anything was asked would be a claim, not a result.
	$lblUpd = New-Object System.Windows.Forms.Label; $lblUpd.Left = 16; $lblUpd.Top = 164; $lblUpd.Text = ''; $lblUpd.AutoSize = $true; $lblUpd.MaximumSize = New-Object System.Drawing.Size(380, 0)
	$chkUpd = New-Object System.Windows.Forms.CheckBox; $chkUpd.Left = 16; $chkUpd.Top = 190; $chkUpd.Text = (T 'box.update_check'); $chkUpd.AutoSize = $true; $chkUpd.Checked = [bool]$State.UpdateCheck
	$avatarImg = Get-EmbeddedImage -Base64 $ernolfB64 # Avatar on the right
	$pb = $null
	if ($avatarImg) { $pb = New-Object System.Windows.Forms.PictureBox; $pb.Width = 96; $pb.Height = 96; $pb.SizeMode = 'Zoom'; $pb.Image = $avatarImg; $pb.Left = $f.ClientSize.Width - $pb.Width - 16; $pb.Top = 16; $pb.Anchor = 'Top, Right' }
	$ok = New-Object System.Windows.Forms.Button; $ok.Text = (T 'button.ok'); $ok.Width = 80; $ok.Height = $script:ButtonXH; $ok.Left = $f.ClientSize.Width - $ok.Width - 16; $ok.Top = $f.ClientSize.Height - $ok.Height - 16; $ok.Anchor = 'Bottom, Right'; $ok.Add_Click({ $f.Close() })
	# Wide enough for the text it carries in this language, and no wider -- a width
	# written down here is a width that is wrong in the next one.
	$btnUpd = New-Object System.Windows.Forms.Button; $btnUpd.Text = (T 'button.check_update'); $btnUpd.Height = $script:ButtonXH
	$btnUpd.Width = [Math]::Max($script:ButtonMinW, ([System.Windows.Forms.TextRenderer]::MeasureText($btnUpd.Text, $f.Font).Width + 24))
	$btnUpd.Left = 16; $btnUpd.Top = $f.ClientSize.Height - $btnUpd.Height - 16; $btnUpd.Anchor = 'Bottom, Left'
	# It takes the place of the check rather than standing next to it: two buttons
	# side by side fit in English and run into the OK button in the next language,
	# and once the answer is on screen there is nothing left to check.
	$btnGet = New-Object System.Windows.Forms.Button; $btnGet.Text = (T 'button.update_now'); $btnGet.Height = $script:ButtonXH
	$btnGet.Width = [Math]::Max($script:ButtonMinW, ([System.Windows.Forms.TextRenderer]::MeasureText($btnGet.Text, $f.Font).Width + 24))
	$btnGet.Left = $btnUpd.Left; $btnGet.Top = $btnUpd.Top; $btnGet.Anchor = 'Bottom, Left'; $btnGet.Visible = $false
	$btnUpd.Add_Click({
			$this.Enabled = $false
			$lblUpd.Text = (T 'label.update_checking')
			# The request holds this thread for as long as the server needs, so the line
			# has to be on screen before it starts rather than after it is over.
			$lblUpd.Refresh()
			$info = Get-UpdateInfo
			$shown = if ($info.Version) { $info.Version.ToString() } else { $info.Tag }
			if (-not $info.Ok) { $lblUpd.Text = (T 'label.update_failed') }
			elseif ($info.Newer) { $lblUpd.Text = (T 'label.update_available' @{ version = $shown }) }
			else { $lblUpd.Text = (T 'label.update_current') }
			# Offered only for a release that brought the archive along. Without it there
			# is nothing to install from here, and the project page is the way on.
			if ($info.Ok -and $info.Newer) {
				$script:UpdateOffer = $info
				if ($info.AssetUrl) { $this.Visible = $false; $btnGet.Visible = $true }
			}
			$this.Enabled = $true
		})
	$btnGet.Add_Click({
			$offer = $script:UpdateOffer
			if (-not $offer) { return }
			$shown = if ($offer.Version) { $offer.Version.ToString() } else { $offer.Tag }
			if ((Ask-YesNoQuestT 'prompt.update_now' @{ app = $AppName; version = $shown }) -ne [System.Windows.Forms.DialogResult]::Yes) { return }
			$this.Enabled = $false
			$lblUpd.Text = (T 'label.update_downloading'); $lblUpd.Refresh()
			$ps1 = Save-UpdatePackage -Url $offer.AssetUrl -Size $offer.AssetSize
			if ([string]::IsNullOrEmpty($ps1)) {
				$lblUpd.Text = (T 'label.update_download_failed')
				$this.Visible = $false; $btnUpd.Visible = $true; $this.Enabled = $true
				return
			}
			# Out of the way first: what follows takes the whole application down, and a
			# modal dialog still on screen has a message loop of its own to unwind.
			$f.Close()
			[void](Start-UpdateHandover -ScriptPath $ps1)
		})
	$chkUpd.Add_Click({
			$State.UpdateCheck = [bool]$this.Checked
			Save-Config
		})
	# What a check has already found, from this box or from the one at startup. The
	# balloon named the version and this is where the user comes to act on it, so
	# asking the project page the same question again would only be a way of making
	# the answer arrive later.
	if ($script:UpdateOffer) {
		$shown = if ($script:UpdateOffer.Version) { $script:UpdateOffer.Version.ToString() } else { $script:UpdateOffer.Tag }
		$lblUpd.Text = (T 'label.update_available' @{ version = $shown })
		if ($script:UpdateOffer.AssetUrl) { $btnUpd.Visible = $false; $btnGet.Visible = $true }
	}
	# Dispose avatar image to free GDI handles
	$f.add_FormClosed({ if ($pb -and $pb.Image) { try { $pb.Image.Dispose() } catch {} } })
	if ($pb) { $f.Controls.AddRange(@($lblTit, $lblDes, $lblVer, $lblAut, $link, $lblUpd, $chkUpd, $pb, $btnUpd, $btnGet, $ok)) }
	else { $f.Controls.AddRange(@($lblTit, $lblDes, $lblVer, $lblAut, $link, $lblUpd, $chkUpd, $btnUpd, $btnGet, $ok)) }
	[void]$f.ShowDialog()
}