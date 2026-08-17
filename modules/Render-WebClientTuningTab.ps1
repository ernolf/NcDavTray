function Render-WebClientTuningTab([Parameter(Mandatory)][System.Windows.Forms.TabPage]$HostTab) {
	# --- Read current registry values (no elevation to read) ---
	$cur = try { Get-ItemProperty -Path $RegWebClient -ErrorAction Stop } catch { $null }
	$get = { param($n, $def) if ($cur -and ($cur.PSObject.Properties.Name -contains $n)) { [int64]$cur.$n } else { [int64]$def } }
	# Defaults from MS docs https://learn.microsoft.com/en-us/iis/publish/using-webdav/using-the-webdav-redirector#webdav-redirector-registry-settings
	$v_BasicAuthLevel = & $get 'BasicAuthLevel' 1 # 1 = Basic only over SSL (recommended)
	$v_FileSizeLimitInBytes = & $get 'FileSizeLimitInBytes' 52428800 # 50 MB default = 50000000
	$v_FileAttributesLimitInBytes = & $get 'FileAttributesLimitInBytes' 1048576 # 1 MB default = 1000000 (~1000 files)
	$v_LocalTimeoutInSec = & $get 'LocalServerTimeoutInSec' 15
	$v_InternetTimeoutInSec = & $get 'InternetServerTimeoutInSec' 30
	$v_SendReceiveTimeoutInSec = & $get 'SendReceiveTimeoutInSec' 60
	$v_NotFoundCacheLifetimeInSec = & $get 'ServerNotFoundCacheLifeTimeInSec' 60
	# --- Layout base ---
	$t = $HostTab
	$t.Controls.Clear()
	# Small helpers
	function Format-Bytes([long]$b) { if ($b -ge 1GB) { '{0:N1} GB' -f ($b/1GB) } elseif ($b -ge 1MB) { '{0:N0} MB' -f ($b/1MB) } else { '{0:N0} B' -f $b } }
	# --- Group: Authentication ---
	$grpAuth = New-Object Windows.Forms.Panel; $grpAuth.Left = 8; $grpAuth.Top = 8; $grpAuth.Width = $t.ClientSize.Width - 16; $grpAuth.Height = 40; $grpAuth.Anchor = 'Top, Left, Right'
	$lblBAL = $script:LabelBasicAuthLevel = New-Object Windows.Forms.Label; $lblBAL.Text = (T 'label.basic_auth_level'); $lblBAL.Left = 12; $lblBAL.Top = 8; $lblBAL.AutoSize = $true
	$cmbBAL = $script:ComboBoxBasicAuthLevel = New-Object Windows.Forms.ComboBox; $cmbBAL.Width = 340; $cmbBAL.Left = $grpAuth.Width - $cmbBAL.Width; $cmbBAL.Top = $lblBAL.Top - 4; $cmbBAL.DropDownStyle = 'DropDownList'; $cmbBAL.Anchor = 'Top, Right'
	$opt = @( @{ v = 0; s = (T 'combo.basic_auth_level_0') }, @{ v = 1; s = (T 'combo.basic_auth_level_1') }, @{ v = 2; s = (T 'combo.basic_auth_level_2') } )
	foreach($o in $opt) { [void]$cmbBAL.Items.Add($o.s) }
	# Preselect "1" as safe default (find index of option with v = = 1)
	$selectedIdx = 0; for ($i = 0; $i -lt $opt.Count; $i++) { if ([int]$opt[$i].v -eq 1) { $selectedIdx = $i; break } }
	# If registry has a specific value, prefer that when present in options
	$desired = 1; try { $desired = [int]$v_BasicAuthLevel } catch { $desired = 1 }
	for ($i = 0; $i -lt $opt.Count; $i++) { if ([int]$opt[$i].v -eq $desired) { $selectedIdx = $i; break } }
	$cmbBAL.SelectedIndex = $selectedIdx
	$script:Tip.SetToolTip($cmbBAL, (T 'tip.basic_auth'))
	$script:BalGuard = $false
	$cmbBAL.add_SelectedIndexChanged(({
		if ($script:BalGuard) { return }
		$idx = $this.SelectedIndex
		if ($idx -eq 0 -or $idx -eq 2) {
			$key = if ($idx -eq 0) { 'prompt.basic_auth_0_warning' } else { 'prompt.basic_auth_2_warning' }
			$ans = Ask-YesNoWarnT $key
			if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { $script:BalGuard = $true; $this.SelectedIndex = 1; $script:BalGuard = $false }
		}
		if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
	}).GetNewClosure())
	$grpAuth.Controls.AddRange(@($lblBAL, $cmbBAL))
	$t.Controls.Add($grpAuth)
	# --- Group: Limits ---
	$grpLim = New-Object Windows.Forms.Panel; $grpLim.Left = 8; $grpLim.Top = $grpAuth.Bottom + 8; $grpLim.Width = $t.ClientSize.Width - 16; $grpLim.Height = 65; $grpLim.Anchor = 'Top, Left, Right'
	# FileAttributesLimit: map "files per folder" -> bytes (rule of thumb: ~1000 bytes per file)
	$lblFAL = $script:LabelFilesPerFolder = New-Object Windows.Forms.Label; $lblFAL.Text = (T 'label.file_attributes_limit'); $lblFAL.Left = 12; $lblFAL.Top = 4; $lblFAL.AutoSize = $true
	$numFiles = New-Object Windows.Forms.NumericUpDown; $numFiles.Left = $cmbBAL.Left + 80; $numFiles.Top = $lblFAL.Top - 2; $numFiles.Anchor = 'Top, Right'
	$numFiles.Minimum = 50; $numFiles.Maximum = 4294967295; $numFiles.Increment = 50; $numFiles.Width = 80
	# derive initial files-per-folder from current bytes (floor)
	$numFiles.Value = [decimal]([Math]::Max(50, [int]([double]$v_FileAttributesLimitInBytes / 1000)))
	$numFiles.add_ValueChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	# FileSizeLimit: slider-ish via discrete steps (human friendly)
	$lblFSL = New-Object Windows.Forms.Label; $lblFSL.Text = (T 'label.file_size_limit'); $lblFSL.Left = 12; $lblFSL.Top = 38; $lblFSL.AutoSize = $true
	$steps = @(50MB, 100MB, 200MB, 500MB, 1GB, 2GB, 4GB)
	$cmbFSL = New-Object Windows.Forms.ComboBox
	$cmbFSL.Left = $cmbBAL.Left + 80; $cmbFSL.Top = $lblFSL.Top - 4; $cmbFSL.Width = 80; $cmbFSL.DropDownStyle = 'DropDownList'; $cmbFSL.Anchor = 'Top, Right'
	foreach($s in $steps) { [void]$cmbFSL.Items.Add((Format-Bytes $s)) }
	$sel = $steps | Select-Object @{n = 'd'; e = { [math]::Abs($_ - $v_FileSizeLimitInBytes) }}, @{n = 'v'; e = {$_}} | Sort-Object d | Select-Object -First 1
	$cmbFSL.SelectedIndex = [Array]::IndexOf($steps, $sel.v)
	$cmbFSL.add_SelectedIndexChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	# current registry value labels for limits
	$script:lblFALCur = New-Object Windows.Forms.Label
	$script:lblFALCur.AutoSize = $true; $script:lblFALCur.Top = $lblFAL.Top; $script:lblFALCur.Left = $numFiles.Left + 100; $script:lblFALCur.Anchor = 'Top, Right'
	$script:lblFSLCur = New-Object Windows.Forms.Label
	$script:LabelFileSizeLimit = $lblFSL
	$script:lblFSLCur.AutoSize = $true; $script:lblFSLCur.Top = $lblFSL.Top; $script:lblFSLCur.Left = $script:lblFALCur.Left; $script:lblFSLCur.Anchor = 'Top, Right'
	$grpLim.Controls.AddRange(@($lblFAL, $numFiles, $lblFSL, $cmbFSL, $script:lblFALCur, $script:lblFSLCur))
	$t.Controls.Add($grpLim)
	# --- Group: Timeouts ---
	$grpTo = New-Object Windows.Forms.Panel; $grpTo.Left = 8; $grpTo.Top = $grpLim.Bottom + 8; $grpTo.Width = $t.ClientSize.Width - 16; $grpTo.Height = 150; $grpTo.Anchor = 'Top, Left, Right'
	# Measured, because Microsoft documents the two values but not the criterion: the
	# redirector picks the timeout from the shape of the host name alone. A name without
	# a dot is a local server, everything else, every FQDN and every IP address, is an
	# internet server. The Windows security zone has no influence on this.
	$lblSco = $script:LabelLocalTimeoutNote = New-Object Windows.Forms.Label; $lblSco.Text = (T 'label.local_timeout_note'); $lblSco.Left = 4; $lblSco.Top = 0; $lblSco.AutoSize = $true
	if ($script:Tip) { $script:Tip.SetToolTip($lblSco, (T 'tip.local_timeout_note')) }
	$lblLoc = $script:LabelLocalServerTimeout = New-Object Windows.Forms.Label; $lblLoc.Text = (T 'label.local_server_timeout'); $lblLoc.Left = 12; $lblLoc.Top = 30; $lblLoc.AutoSize = $true
	$btnHelpLoc = $script:ButtonLocalServerTimeoutHelp = New-Object Windows.Forms.Button; $btnHelpLoc.Text = '?'; $btnHelpLoc.Width = 28; $btnHelpLoc.Left = $cmbBAL.Left + 80; $btnHelpLoc.Top = $lblLoc.Top - 6; $btnHelpLoc.Height = $script:ButtonH; $btnHelpLoc.Anchor = 'Top, Right'
	if ($script:Tip) { $script:Tip.SetToolTip($btnHelpLoc, (T 'tip.local_server_timeout_help')) }
	$btnHelpLoc.Add_Click({ $parent = $this.FindForm(); [void](Show-HelpT -TitleKey 'label.local_server_timeout' -BodyKey 'message.local_server_timeout_help' -Width 580 -Height 270 -Parent $parent) })
	$numLoc = $script:NumericLocalServerTimeout = New-Object Windows.Forms.NumericUpDown; $numLoc.Left = $btnHelpLoc.Left + 32; $numLoc.Top = $lblLoc.Top - 2; $numLoc.Minimum = 5; $numLoc.Maximum = 600; $numLoc.Value = $v_LocalTimeoutInSec; $numLoc.Width = 80 - 32; $numLoc.Anchor = 'Top, Right'
	$lblInt = $script:LabelInternetServerTimeout = New-Object Windows.Forms.Label; $lblInt.Text = (T 'label.internet_server_timeout'); $lblInt.Left = 12; $lblInt.Top = 60; $lblInt.AutoSize = $true
	$btnHelpInt = $script:ButtonInternetServerTimeoutHelp = New-Object Windows.Forms.Button; $btnHelpInt.Text = '?'; $btnHelpInt.Width = 28; $btnHelpInt.Left = $btnHelpLoc.Left; $btnHelpInt.Top = $lblInt.Top - 6; $btnHelpInt.Height = $script:ButtonH; $btnHelpInt.Anchor = 'Top, Right'
	if ($script:Tip) { $script:Tip.SetToolTip($btnHelpInt, (T 'tip.internet_server_timeout_help')) }
	$btnHelpInt.Add_Click({ $parent = $this.FindForm(); [void](Show-HelpT -TitleKey 'label.internet_server_timeout' -BodyKey 'message.internet_server_timeout_help' -Width 580 -Height 270 -Parent $parent) })
	$numInt = New-Object Windows.Forms.NumericUpDown; $numInt.Left = $btnHelpInt.Left + 32; $numInt.Top = $lblInt.Top - 2; $numInt.Minimum = 5; $numInt.Maximum = 1800; $numInt.Value = $v_InternetTimeoutInSec; $numInt.Width = 80 - 32; $numInt.Anchor = 'Top, Right'
	$lblSR = $script:LabelSendReceiveTimeout = New-Object Windows.Forms.Label; $lblSR.Text = (T 'label.send_receive_timeout'); $lblSR.Left = 12; $lblSR.Top = 90; $lblSR.AutoSize = $true
	$btnHelpSR = $script:ButtonSendReceiveTimeoutHelp = New-Object Windows.Forms.Button; $btnHelpSR.Text = '?'; $btnHelpSR.Width = 28; $btnHelpSR.Left = $btnHelpLoc.Left; $btnHelpSR.Top = $lblSR.Top - 6; $btnHelpSR.Height = $script:ButtonH; $btnHelpSR.Anchor = 'Top, Right'
	if ($script:Tip) { $script:Tip.SetToolTip($btnHelpSR, (T 'tip.send_receive_timeout_help')) }
	$btnHelpSR.Add_Click({ $parent = $this.FindForm(); [void](Show-HelpT -TitleKey 'label.send_receive_timeout' -BodyKey 'message.send_receive_timeout_help' -Width 580 -Height 270 -Parent $parent) })
	$numSR = New-Object Windows.Forms.NumericUpDown; $numSR.Left = $btnHelpSR.Left + 32; $numSR.Top = $lblSR.Top - 2; $numSR.Minimum = 5; $numSR.Maximum = 1800; $numSR.Value = $v_SendReceiveTimeoutInSec; $numSR.Width = 80 - 32; $numSR.Anchor = 'Top, Right'
	$lblC = $script:LabelServerNotFoundCacheLifeTime = New-Object Windows.Forms.Label; $lblC.Text = (T 'label.server_not_found_cache_lifetime'); $lblC.Left = 12; $lblC.Top = 120; $lblC.AutoSize = $true
	$btnHelpC = $script:ButtonServerNotFoundCacheLifeTimeHelp = New-Object Windows.Forms.Button; $btnHelpC.Text = '?'; $btnHelpC.Width = 28; $btnHelpC.Left = $btnHelpLoc.Left; $btnHelpC.Top = $lblC.Top - 6; $btnHelpC.Height = $script:ButtonH; $btnHelpC.Anchor = 'Top, Right'
	if ($script:Tip) { $script:Tip.SetToolTip($btnHelpC, (T 'tip.server_not_found_cache_lifetime_help')) }
	$btnHelpC.Add_Click({ $parent = $this.FindForm(); [void](Show-HelpT -TitleKey 'label.server_not_found_cache_lifetime' -BodyKey 'message.server_not_found_cache_lifetime_help' -Width 580 -Height 330 -Parent $parent) })
	$numC = New-Object Windows.Forms.NumericUpDown; $numC.Left = $btnHelpC.Left + 32; $numC.Top = $lblC.Top - 2; $numC.Minimum = 5; $numC.Maximum = 86400; $numC.Value = $v_NotFoundCacheLifetimeInSec; $numC.Width = 80 - 32; $numC.Anchor = 'Top, Right'
	$numLoc.add_ValueChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	$numInt.add_ValueChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	$numSR.add_ValueChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	$numC.add_ValueChanged({ if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton } })
	# current registry value labels for timeouts
	$script:LabelLocalServerTimeoutCur = New-Object Windows.Forms.Label; $script:LabelLocalServerTimeoutCur.AutoSize = $true; $script:LabelLocalServerTimeoutCur.Top = $lblLoc.Top; $script:LabelLocalServerTimeoutCur.Left = $script:lblFALCur.Left; $script:LabelLocalServerTimeoutCur.Anchor = 'Top, Right'
	$script:LabelInternetServerTimeoutCur = New-Object Windows.Forms.Label; $script:LabelInternetServerTimeoutCur.AutoSize = $true; $script:LabelInternetServerTimeoutCur.Top = $lblInt.Top; $script:LabelInternetServerTimeoutCur.Left = $script:lblFALCur.Left; $script:LabelInternetServerTimeoutCur.Anchor = 'Top, Right'
	$script:LabelSendReceiveTimeoutCur = New-Object Windows.Forms.Label; $script:LabelSendReceiveTimeoutCur.AutoSize = $true; $script:LabelSendReceiveTimeoutCur.Top = $lblSR.Top; $script:LabelSendReceiveTimeoutCur.Left = $script:lblFALCur.Left; $script:LabelSendReceiveTimeoutCur.Anchor = 'Top, Right'
	$script:LabelServerNotFoundCacheLifeTimeCur = New-Object Windows.Forms.Label; $script:LabelServerNotFoundCacheLifeTimeCur.AutoSize = $true; $script:LabelServerNotFoundCacheLifeTimeCur.Top = $lblC.Top; $script:LabelServerNotFoundCacheLifeTimeCur.Left = $script:lblFALCur.Left; $script:LabelServerNotFoundCacheLifeTimeCur.Anchor = 'Top, Right'
	$grpTo.Controls.AddRange(@(
		$lblSco,
		$lblLoc, $btnHelpLoc, $numLoc, $script:LabelLocalServerTimeoutCur,
		$lblInt, $btnHelpInt, $numInt, $script:LabelInternetServerTimeoutCur,
		$lblSR, $btnHelpSR, $numSR, $script:LabelSendReceiveTimeoutCur,
		$lblC, $btnHelpC, $numC, $script:LabelServerNotFoundCacheLifeTimeCur
	))
	$t.Controls.Add($grpTo)
	# --- Group: WebClient service ---
	$grpSvc = New-Object Windows.Forms.Panel; $grpSvc.Left = 8; $grpSvc.Top = $grpTo.Bottom + 8; $grpSvc.Width = $t.ClientSize.Width - 16; $grpSvc.Height = 78; $grpSvc.Anchor = 'Top, Left, Right'
	$lblSvc = $script:LabelServiceStatus = New-Object Windows.Forms.Label
	$lblSvc.Left = 12; $lblSvc.Top = 8; $lblSvc.AutoSize = $true; $lblSvc.Anchor = 'Top, Left'
	$lblSvc.Padding = New-Object System.Windows.Forms.Padding(0,0,22,0) # reserve some space for LED
	$lblSvc.Text = (T 'label.service_status')
	# draw traffic-light LED after the label text
	$lblSvc.add_Paint({
		param($sender, $e)
		try {
			$lbl = [System.Windows.Forms.Label]$sender; $g = $e.Graphics; $text = $lbl.Text
			if ([string]::IsNullOrEmpty($text)) { return }
			# measure text in current font
			$textSize = $g.MeasureString($text, $lbl.Font)
			# LED size
			$diam = [float]([Math]::Ceiling($lbl.Font.Height * 0.85))
			$y = ($lbl.Height - $diam) / 2 - 1 # move LED a bit up
			# a bit more distance from text
			$x = [Math]::Ceiling($textSize.Width) + 8
			if ($x + $diam -gt $lbl.Width) { $x = $lbl.Width - $diam - 2 }
			# colors from Tag (SetWebClientStatusLabel)
			$fillColor = [System.Drawing.Color]::DarkGray
			$borderColor = [System.Drawing.Color]::Black
			$state = $null
			if ($lbl.Tag) { if ($lbl.Tag.Color) { $fillColor = $lbl.Tag.Color }; if ($lbl.Tag.BorderColor) { $borderColor = $lbl.Tag.BorderColor }; if ($lbl.Tag.State) { $state = $lbl.Tag.State } }
			$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
			# filled LED
			$brushDot = New-Object System.Drawing.SolidBrush($fillColor); $g.FillEllipse($brushDot, $x, $y, $diam, $diam); $brushDot.Dispose()
			# outline so it is clearly visible
			$penBorder = New-Object System.Drawing.Pen($borderColor, 1.2); $g.DrawEllipse($penBorder, $x, $y, $diam, $diam); $penBorder.Dispose()
			# for "<not found>" draw a white cross inside the red LED
			if ($state -eq '<not found>') {
				$penX = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 1.4)
				$margin = 3
				$g.DrawLine($penX, $x + $margin, $y + $margin, $x + $diam - $margin, $y + $diam - $margin)
				$g.DrawLine($penX, $x + $diam - $margin, $y + $margin, $x + $margin, $y + $diam - $margin)
				$penX.Dispose()
			}
		} catch {}
	})
	$lblST = $script:LabelServiceStartType = New-Object Windows.Forms.Label; $lblST.Text = (T 'label.service_starttype')
	$lblST.Left = $cmbBAL.Left - 55; $lblST.Top = $lblSvc.Top; $lblST.AutoSize = $true; $lblST.Anchor = 'Top, Right'
	# Trigger info button below start type
	$btnTrig = $script:ButtonServiceTriggerInfo = New-Object Windows.Forms.Button; $btnTrig.Text = (T 'button.triggerinfo')
	$btnTrig.Width = 170; $btnTrig.Height = $script:ButtonH; $btnTrig.Left = $grpSvc.Width - $btnTrig.Width; $btnTrig.Top = $lblSvc.Top - 6; $btnTrig.Anchor = 'Top, Right'
	$btnTrig.Visible = $false
	$btnTrig.Add_Click({ Get-WebClientTriggerInfoText -ServiceName 'WebClient' -Output 'Window' })
	# Startup type combo (Automatic / Manual / Disabled)
	$cmbSvc = $script:ComboServiceStartType = New-Object Windows.Forms.ComboBox
	$cmbSvc.Left = $cmbBAL.Left + 60; $cmbSvc.Width = $btnTrig.Left - $cmbSvc.Left - 10; $cmbSvc.Top = $lblSvc.Top - 4
	$cmbSvc.DropDownStyle = 'DropDownList'; $cmbSvc.Anchor = 'Top, Right'
	# Fixed order: 0 = Automatic, 1 = Manual, 2 = Disabled
	[void]$cmbSvc.Items.Add((T 'combo.webclient_start_automatic'))
	[void]$cmbSvc.Items.Add((T 'combo.webclient_start_manual'))
	[void]$cmbSvc.Items.Add((T 'combo.webclient_start_disabled'))
	$script:SvcStartPrevIdx = 0
	$cmbSvc.add_SelectedIndexChanged({
		$idx = $this.SelectedIndex
		# Determine current real service start type
		$startIsDisabled = $false
		try { $svc = Get-Service -Name WebClient -ErrorAction Stop; $startRaw = [string]$svc.StartType; if ($startRaw -like 'Disabled*') { $startIsDisabled = $true } } catch { $startIsDisabled = $false }
		if ($idx -eq 2) {
			# Only warn if the IS state is NOT already Disabled
			if (-not $startIsDisabled) {
				$ans = Ask-YesNoWarnT 'prompt.start_disabled_warn'
				# Revert to previous index
				if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { if ($script:SvcStartPrevIdx -ge 0 -and $script:SvcStartPrevIdx -lt $this.Items.Count) { $this.SelectedIndex = $script:SvcStartPrevIdx }; return }
			}
			$script:SvcStartPrevIdx = $idx
		} else { $script:SvcStartPrevIdx = $idx }
		if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
	}.GetNewClosure())
	# Buttons share the same position and toggle visibility depending on service state
	$btnSvcRestart = $script:ButtonServiceRestart = New-Object Windows.Forms.Button; $btnSvcRestart.Text = (T 'button.restart_service'); $btnSvcRestart.Top = 38; $btnSvcRestart.Left = 12; $btnSvcRestart.Height = $script:UacButtonH; $btnSvcRestart.AutoSize = $true; $btnSvcRestart.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$btnSvcStart = $script:ButtonServiceStart = New-Object Windows.Forms.Button; $btnSvcStart.Text = (T 'button.start_service'); $btnSvcStart.Top = 38; $btnSvcStart.Left = 12; $btnSvcStart.Height = $script:UacButtonH; $btnSvcStart.AutoSize = $true; $btnSvcStart.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$grpSvc.Controls.AddRange(@($lblSvc, $lblST, $cmbSvc, $btnTrig, $btnSvcRestart, $btnSvcStart))
	$t.Controls.Add($grpSvc)
	# --- script-scoped async invoker with live polling (no extra runspace) ---
	$script:InvokeWebClientActionAsync = {
		param([ValidateSet('start', 'restart')][string]$Action)
		# mark that we are driving the service state ourselves
		$script:SvcActionPending = $true
		# immediate visual feedback (safe guards)
		if ($script:SetWebClientStatusLabel -is [scriptblock]) { $st = if ($Action -eq 'restart') { 'StopPending' } else { 'StartPending' }; & $script:SetWebClientStatusLabel $st }
		if ($script:ButtonServiceStart -is [Windows.Forms.Button] -and -not $script:ButtonServiceStart.IsDisposed) { $script:ButtonServiceStart.Visible = $false }
		if ($script:ButtonServiceRestart -is [Windows.Forms.Button] -and -not $script:ButtonServiceRestart.IsDisposed) { $script:ButtonServiceRestart.Visible = $false }
		# live polling while elevated action runs
		$poll = New-Object System.Windows.Forms.Timer; $poll.Interval = 300
		$poll.add_Tick({
			try {
				$st = (Get-Service -Name WebClient -ErrorAction Stop).Status.ToString()
				if ($script:SetWebClientStatusLabel -is [scriptblock]) { & $script:SetWebClientStatusLabel $st }
			} catch { if ($script:SetWebClientStatusLabel -is [scriptblock]) { & $script:SetWebClientStatusLabel '<not found>' } }
		})
		$poll.Start()
		# launch elevation without waiting (lets UAC appear; UI stays responsive)
		$launched = Invoke-WebClientServiceAction $Action -NoWait
		if (-not $launched) {
			try { $poll.Stop(); $poll.Dispose() } catch {}
			$script:SvcActionPending = $false
			& $script:UpdateSvc
			try { Show-ErrorT 'message.uac_admin_required' } catch {}
			return
		}
		# stop polling when state stabilizes
		$stopper = New-Object System.Windows.Forms.Timer; $stopper.Interval = 1000
		$stopper.add_Tick({
			try {
				$st = (Get-Service -Name WebClient -ErrorAction Stop).Status
				if ($st -in [System.ServiceProcess.ServiceControllerStatus]::Running, [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
					try { if ($poll) { $poll.Stop(); $poll.Dispose(); $poll = $null } } catch {}
					try { if ($stopper) { $stopper.Stop(); $stopper.Dispose(); $stopper = $null } } catch {}
					$script:SvcActionPending = $false
					& $script:UpdateSvc
				}
			} catch {
				try { if ($poll) { $poll.Stop(); $poll.Dispose(); $poll = $null } } catch {}
				try { if ($stopper) { $stopper.Stop(); $stopper.Dispose(); $stopper = $null } } catch {}
				$script:SvcActionPending = $false
				& $script:UpdateSvc
			}
		})
		$stopper.Start()
	}
	# small helper: map WebClient state to LED color + tooltip
	$script:SetWebClientStatusLabel = {
		param([string]$stateText)
		try {
			if ($script:LabelServiceStatus -is [Windows.Forms.Label] -and -not $script:LabelServiceStatus.IsDisposed) {
				# saturated LED colors
				$greenFill = [System.Drawing.Color]::FromArgb(0, 255, 0); $greenBorder = [System.Drawing.Color]::FromArgb(0, 120, 0)
				$redFill = [System.Drawing.Color]::FromArgb(255, 0, 0); $redBorder = [System.Drawing.Color]::FromArgb(120, 0, 0)
				$orangeFill = [System.Drawing.Color]::FromArgb(255, 165, 0); $orangeBorder = [System.Drawing.Color]::FromArgb(180, 90, 0)
				$defaultBorder = [System.Drawing.Color]::FromArgb(40, 40, 40); $fillColor = [System.Drawing.Color]::DarkGray; $borderColor = $defaultBorder
				switch ($stateText) {
					'Running' { $fillColor = $greenFill; $borderColor = $greenBorder; break; }
					'Stopped' { $fillColor = $redFill; $borderColor = $redBorder; break }
					'<not found>' { $fillColor = $redFill; $borderColor = $redBorder; break }
					default { if ($stateText -like '*Pending' -or $stateText -eq 'Paused') { $fillColor = $orangeFill; $borderColor = $orangeBorder } break }
				}
				# store for Paint handler
				$script:LabelServiceStatus.Tag = [pscustomobject]@{ Color = $fillColor; BorderColor = $borderColor; State = $stateText }
				$script:LabelServiceStatus.Invalidate()
				# localized status text for tooltip
				$locStatus = switch ($stateText) { 'Running' { T 'status.running' }; 'Stopped' { T 'status.stopped' }; '<not found>' { T 'status.not_found' }; default { T 'status.pending' } }
				# tooltip shows full localized state text
				if ($script:Tip) { $script:Tip.SetToolTip( $script:LabelServiceStatus, (T 'tip.service_status' @{ status = $locStatus }) ) }
			}
		} catch {}
	}
	$script:UpdateSvc = {
		try {
			# Sync script-level flag and reuse returned service object
			$s = Sync-WebClientDeactivatedFlag
			if (-not $s) { throw 'WebClient service not available' }
			$state = [string]$s.Status
			$startRaw = [string]$s.StartType; $startMode = 'Manual'
			# Normalize startup mode to Automatic / Manual / Disabled
			switch -Regex ($startRaw) { '^Automatic' { $startMode = 'Automatic'; break }; '^Disabled' { $startMode = 'Disabled'; break }; default { $startMode = 'Manual'; break } }
			# Status label with placeholder (centralized helper)
			if ($script:SetWebClientStatusLabel -is [scriptblock]) { & $script:SetWebClientStatusLabel $state }
			# Startup-type combo + trigger button visibility
			if ($cmbSvc -and -not $cmbSvc.IsDisposed) {
				$hasTrigger = Test-Path $($RegWebClient -replace 'Parameters', 'TriggerInfo')
				if ($btnTrig -and -not $btnTrig.IsDisposed) { $btnTrig.Visible = $hasTrigger }
				# Map normalized start mode to fixed index: 0 = Automatic, 1 = Manual, 2 = Disabled
				$idx = switch ($startMode) { 'Automatic' { 0 }; 'Disabled' { 2 }; default { 1 } }
				if ($idx -ge 0 -and $idx -lt $cmbSvc.Items.Count) { $cmbSvc.SelectedIndex = $idx; $script:SvcStartPrevIdx = $idx } else { $cmbSvc.SelectedIndex = -1 }
			}
			# Keep global "service deactivated" flag in sync with startup mode
			$wasDeactivated = [bool]$script:ServiceDeactivated
			$nowDeactivated = ($startMode -eq 'Disabled')
			$script:ServiceDeactivated = $nowDeactivated
			if ($nowDeactivated -and -not $wasDeactivated) {
				# Service has just been disabled -> unmap the drives and show the tray state.
				try { Unmap-OwnDrives } catch {}
				try { Set-TrayServiceDeactivated } catch {}
			}
			# Service control buttons: respect StartType
			if ($script:ButtonServiceStart -is [Windows.Forms.Button] -and -not $script:ButtonServiceStart.IsDisposed) {
				# Show Start but gray it out while service is disabled
				if ($startMode -eq 'Disabled') { $script:ButtonServiceStart.Visible = $true; $script:ButtonServiceStart.Enabled = $false }
				else { $script:ButtonServiceStart.Visible = ($state -ne 'Running'); $script:ButtonServiceStart.Enabled = $true }
			}
			if ($script:ButtonServiceRestart -is [Windows.Forms.Button] -and -not $script:ButtonServiceRestart.IsDisposed) {
				# No restart when the service is disabled
				if ($startMode -eq 'Disabled') { $script:ButtonServiceRestart.Visible = $false } else { $script:ButtonServiceRestart.Visible = ($state -eq 'Running') }
			}
		}
		catch {
			if ($script:SetWebClientStatusLabel -is [scriptblock]) { & $script:SetWebClientStatusLabel '<not found>' }
			if ($cmbSvc -and -not $cmbSvc.IsDisposed) { $cmbSvc.SelectedIndex = -1 }
			if ($script:ButtonServiceStart -is [Windows.Forms.Button] -and -not $script:ButtonServiceStart.IsDisposed) { $script:ButtonServiceStart.Visible = $true; $script:ButtonServiceStart.Enabled = $false }
			if ($script:ButtonServiceRestart -is [Windows.Forms.Button] -and -not $script:ButtonServiceRestart.IsDisposed) { $script:ButtonServiceRestart.Visible = $false }
		}
	}
	# --- Footer: Apply (admin) left of Close ---
	$footer = New-Object Windows.Forms.Panel; $footer.Dock = 'Bottom'; $footer.Height = $script:UacFooterH
	$t.Controls.Add($footer)
	$btnClose = $script:ButtonClose2 = New-Object Windows.Forms.Button; $btnClose.Text = (T 'button.close')
	$btnClose.Width = 100; $btnClose.Left = $footer.ClientSize.Width - $btnClose.Width - 2; $btnClose.Height = $script:ButtonXH; $btnClose.Top = [int]($script:UacButtonH - $btnClose.Height); $btnClose.Anchor = 'Top, Right'
	$btnApply = $script:ButtonApplyAsAdmin = New-Object Windows.Forms.Button; $btnApply.Text = (T 'button.uac_apply_changes')
	$btnApply.AutoSize = $true; $btnApply.AutoSizeMode = [System.Windows.Forms.AutoSizeMode]::GrowAndShrink
	$btnApply.Left = $btnClose.Left - $btnApply.Width - 10; $btnApply.Height = $script:UacButtonH; $btnApply.Anchor = 'Top, Right'
	$footer.Controls.AddRange(@($btnApply, $btnClose))
	# Dirty tracking: compare live registry values with current UI values
	$script:UpdateWebClientApplyButton = {
		try {
			if (-not $btnApply -or $btnApply.IsDisposed) { return }
			# Read current registry snapshot
			try { $curNow = Get-ItemProperty -Path $RegWebClient -ErrorAction Stop } catch { $curNow = $null }
			$raw = { param($n, $def, $src); if ($src -and ($src.PSObject.Properties.Name -contains $n)) { try { return [int64]$src.$n } catch { return $def } }; return $def }
			$maxDword = [uint32]::MaxValue
			# Service startup type (service side)
			$startReg = $null
			try {
				$s = Get-Service -Name WebClient -ErrorAction Stop
				$startRaw = [string]$s.StartType
				switch -Regex ($startRaw) { '^Automatic' { $startReg = 'Automatic'; break }; '^Disabled' { $startReg = 'Disabled'; break }; default { $startReg = 'Manual'; break } }
			} catch { $startReg = $null }
			# Registry side (canonical 32-bit range)
			$balReg = [int] (& $raw 'BasicAuthLevel' $v_BasicAuthLevel $curNow)
			$attrReg = [int64] (& $raw 'FileAttributesLimitInBytes' $v_FileAttributesLimitInBytes $curNow)
			if ($attrReg -gt $maxDword) { $attrReg = [int64]$maxDword }
			$sizeReg = [int64] (& $raw 'FileSizeLimitInBytes' $v_FileSizeLimitInBytes $curNow)
			if ($sizeReg -gt $maxDword) { $sizeReg = [int64]$maxDword }
			$locReg = [int] (& $raw 'LocalServerTimeoutInSec' $v_LocalTimeoutInSec $curNow)
			$intReg = [int] (& $raw 'InternetServerTimeoutInSec' $v_InternetTimeoutInSec $curNow)
			$srReg = [int] (& $raw 'SendReceiveTimeoutInSec' $v_SendReceiveTimeoutInSec $curNow)
			$nfReg = [int] (& $raw 'ServerNotFoundCacheLifeTimeInSec' $v_NotFoundCacheLifetimeInSec $curNow)
			# UI side (same canonical space)
			$balUi = 1
			if ($cmbBAL.SelectedIndex -ge 0) { $balUi = @(0,1,2)[$cmbBAL.SelectedIndex] }
			$attrUi = [int64]$numFiles.Value * 1000
			if ($attrUi -gt $maxDword) { $attrUi = [int64]$maxDword }
			if ($cmbFSL.SelectedIndex -ge 0) { $sizeUi = [int64]$steps[$cmbFSL.SelectedIndex] } else { $sizeUi = [int64]$steps[0] }
			if ($sizeUi -gt $maxDword) { $sizeUi = [int64]$maxDword }
			$locUi = [int]$numLoc.Value; $intUi = [int]$numInt.Value; $srUi = [int]$numSR.Value; $nfUi = [int]$numC.Value
			# Startup type from UI combo (fixed index mapping)
			$startUi = $null
			if ($cmbSvc -and -not $cmbSvc.IsDisposed -and $cmbSvc.SelectedIndex -ge 0) { $idxStart = $cmbSvc.SelectedIndex; $startUi = switch ($idxStart) { 0 { 'Automatic' }; 1 { 'Manual' }; 2 { 'Disabled' }; default { $null } } }
			$dirty = $false
			if ($balReg -ne $balUi) { $dirty = $true } elseif ($attrReg -ne $attrUi) { $dirty = $true } elseif ($sizeReg -ne $sizeUi) { $dirty = $true } elseif ($locReg -ne $locUi) { $dirty = $true } elseif ($intReg -ne $intUi) { $dirty = $true } elseif ($srReg -ne $srUi) { $dirty = $true } elseif ($nfReg -ne $nfUi) { $dirty = $true }
			elseif ($startReg -ne $startUi -and $startReg -ne $null -and $startUi -ne $null) { $dirty = $true }
			$btnApply.Enabled = $dirty
		} catch {}
	}.GetNewClosure()
	# Initial evaluation
	if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
	$null = $btnSvcStart.Handle; Enable-UacShield $btnSvcStart; $null = $btnSvcRestart.Handle; Enable-UacShield $btnSvcRestart; $null = $btnApply.Handle; Enable-UacShield $btnApply
	# updater (script-scoped so event handlers can call it later)
	$btnSvcStart.Add_Click({ & $script:InvokeWebClientActionAsync -Action 'start' })
	$btnSvcRestart.Add_Click({ & $script:InvokeWebClientActionAsync -Action 'restart' })
	& $script:UpdateSvc
	# Live registry view for raw values (hex / dec)
	if ($script:WebClientRegTimer) { try { $script:WebClientRegTimer.Stop(); $script:WebClientRegTimer.Dispose() } catch {}; $script:WebClientRegTimer = $null }
	$script:UpdateWebClientRegView = {
		try { $curNow = Get-ItemProperty -Path $RegWebClient -ErrorAction Stop } catch { $curNow = $null }
		$raw = { param($n, $def, $src); if ($src -and ($src.PSObject.Properties.Name -contains $n)) { try { return [int64]$src.$n } catch { return $def } }; return $def }
		$fmt = { param($v); if ($v -lt 0) { $v = 0 }; $u = [uint32]$v; return ("0x{0:x8} ({1})" -f $u, $u) }
		if ($script:lblFALCur -and -not $script:lblFALCur.IsDisposed) { $v = & $raw 'FileAttributesLimitInBytes' $v_FileAttributesLimitInBytes $curNow; $script:lblFALCur.Text = & $fmt $v }
		if ($script:lblFSLCur -and -not $script:lblFSLCur.IsDisposed) { $v = & $raw 'FileSizeLimitInBytes' $v_FileSizeLimitInBytes $curNow; $script:lblFSLCur.Text = & $fmt $v }
		if ($script:LabelLocalServerTimeoutCur -and -not $script:LabelLocalServerTimeoutCur.IsDisposed) { $v = & $raw 'LocalServerTimeoutInSec' $v_LocalTimeoutInSec $curNow; $script:LabelLocalServerTimeoutCur.Text = & $fmt $v }
		# The local timeout is dead weight unless a mount names a host without a dot, so
		# the field is only offered when one does. Re-checked here because mounts can be
		# added while this window stays open.
		if ($script:NumericLocalServerTimeout -and -not $script:NumericLocalServerTimeout.IsDisposed) {
			$script:NumericLocalServerTimeout.Enabled = [bool](@($State.Mounts) | Where-Object { $_ -and ([string]$_.Server) -and ([string]$_.Server -notmatch '\.') })
		}
		if ($script:LabelInternetServerTimeoutCur -and -not $script:LabelInternetServerTimeoutCur.IsDisposed) { $v = & $raw 'InternetServerTimeoutInSec' $v_InternetTimeoutInSec $curNow; $script:LabelInternetServerTimeoutCur.Text = & $fmt $v }
		if ($script:LabelSendReceiveTimeoutCur -and -not $script:LabelSendReceiveTimeoutCur.IsDisposed) { $v = & $raw 'SendReceiveTimeoutInSec' $v_SendReceiveTimeoutInSec $curNow; $script:LabelSendReceiveTimeoutCur.Text = & $fmt $v }
		if ($script:LabelServerNotFoundCacheLifeTimeCur -and -not $script:LabelServerNotFoundCacheLifeTimeCur.IsDisposed) { $v = & $raw 'ServerNotFoundCacheLifeTimeInSec' $v_NotFoundCacheLifetimeInSec $curNow; $script:LabelServerNotFoundCacheLifeTimeCur.Text = & $fmt $v }
	}
	$script:WebClientRegTimer = New-Object System.Windows.Forms.Timer; $script:WebClientRegTimer.Interval = 800
	$script:WebClientRegTimer.add_Tick({
		& $script:UpdateWebClientRegView
		if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
		# keep service LED + buttons in sync with real service state, but do not interfere while a Start/Restart action is pending
		if (-not $script:SvcActionPending -and ($script:UpdateSvc -is [scriptblock])) { & $script:UpdateSvc }
	})
	$script:WebClientRegTimer.Start()
	& $script:UpdateWebClientRegView
	& $script:UpdateSvc
	# Apply handler -> elevate via broker
	$btnApply.Add_Click({
		# Map current UI state to registry payload
		$bal = 1
		if ($cmbBAL.SelectedIndex -ge 0) { $bal = @(0,1,2)[$cmbBAL.SelectedIndex] }
		$maxDword = [uint32]::MaxValue
		# Map files-per-folder back to bytes (approx. 1000 bytes per file)
		$limitAttr = [int64]$numFiles.Value * 1000
		if ($limitAttr -gt $maxDword) { $limitAttr = [int64]$maxDword }
		# Map selected step to bytes
		if ($cmbFSL.SelectedIndex -ge 0) { $limitSize = [int64]$steps[$cmbFSL.SelectedIndex] } else { $limitSize = [int64]$steps[0] }
		if ($limitSize -gt $maxDword) { $limitSize = [int64]$maxDword }
		# Startup type from UI (Automatic / Manual / Disabled) – same index pattern as BasicAuth
		$startupMode = $null; $idxStart = $null
		if ($cmbSvc -and -not $cmbSvc.IsDisposed -and $cmbSvc.SelectedIndex -ge 0) { $idxStart = $cmbSvc.SelectedIndex; $startupMode = switch ($idxStart) { 0 { 'Automatic' }; 1 { 'Manual' }; 2 { 'Disabled' }; default { $null } } }
		# If startup type will change from enabled (Automatic/Manual) to Disabled, unmap the WebDAV drive once (without putting the app into "paused" state).
		if ($startupMode -eq 'Disabled') {
			$startIsDisabled = $false
			try { $svc = Get-Service -Name WebClient -ErrorAction Stop; $startRaw = [string]$svc.StartType; if ($startRaw -like 'Disabled*') { $startIsDisabled = $true } } catch { $startIsDisabled = $false }
			if (-not $startIsDisabled) { try { Unmap-OwnDrives } catch {} }
		}
		$new = @{ BasicAuthLevel = [int]$bal; FileAttributesLimitInBytes = $limitAttr; FileSizeLimitInBytes = $limitSize; LocalServerTimeoutInSec = [int]$numLoc.Value; InternetServerTimeoutInSec = [int]$numInt.Value; SendReceiveTimeoutInSec = [int]$numSR.Value; ServerNotFoundCacheLifeTimeInSec = [int]$numC.Value }
		if ($startupMode) { $new.StartupType = $startupMode }
		if (Invoke-WebClientWriteBroker $new) {
			try { Show-InfoT 'message.tuning_applied' } catch {}
			try { & $script:UpdateSvc } catch {}
			# Let registry snapshot + timer decide dirty state
			if ($script:UpdateWebClientApplyButton -is [scriptblock]) { & $script:UpdateWebClientApplyButton }
		} else { try { Show-ErrorT 'message.uac_admin_required' } catch {} }
	}.GetNewClosure())
	# Wire Close button (close parent form)
	$btnClose.Add_Click({ param($s, $e); try { $f = $s.FindForm(); if ($f) { $f.DialogResult = [Windows.Forms.DialogResult]::OK; $f.Close() } } catch {} })
	$t.add_Disposed({
		try {
			$script:UpdateSvc = $null
			$script:ButtonServiceStart = $null
			$script:ButtonServiceRestart = $null
			$script:LabelBasicAuthLevel = $null
			$script:ComboBoxBasicAuthLevel = $null
			$script:LabelFilesPerFolder = $null
			$script:LabelFileSizeLimit = $null
			$script:LabelLocalTimeoutNote = $null
			$script:LabelLocalServerTimeout = $null
			$script:NumericLocalServerTimeout = $null
			$script:LabelInternetServerTimeout = $null
			$script:LabelSendReceiveTimeout = $null
			$script:LabelServerNotFoundCacheLifeTime = $null
			$script:LabelServiceStatus = $null
			$script:LabelServiceStartType = $null
			$script:ButtonServiceTriggerInfo = $null
			$script:ButtonLocalServerTimeoutHelp = $null
			$script:ButtonInternetServerTimeoutHelp = $null
			$script:ButtonSendReceiveTimeoutHelp = $null
			$script:ButtonServerNotFoundCacheLifeTimeHelp = $null
			$script:ButtonApplyAsAdmin = $null
			# dispose shield bitmap and detach from button
			foreach ($b in @($btnSvcStart, $btnSvcRestart, $btnApply)) { try { if ($b -and $b.Tag -and $b.Tag.UacBmp) { $b.Image = $null; $b.Tag.UacBmp.Dispose(); $b.Tag.UacBmp = $null; } } catch {} }
			if ($script:WebClientRegTimer) { try { $script:WebClientRegTimer.Stop(); $script:WebClientRegTimer.Dispose() } catch {}; $script:WebClientRegTimer = $null }
			$script:UpdateWebClientRegView = $null
			$script:lblFALCur = $null; $script:lblFSLCur = $null
			$script:LabelLocalServerTimeoutCur = $null; $script:LabelInternetServerTimeoutCur = $null; $script:LabelSendReceiveTimeoutCur = $null; $script:LabelServerNotFoundCacheLifeTimeCur = $null
			$script:UpdateWebClientApplyButton = $null
			$script:SetWebClientStatusLabel = $null
			$script:SvcStartPrevIdx = $null
		} catch {}
	})
}
