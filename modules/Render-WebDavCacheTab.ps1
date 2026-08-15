function Render-WebDavCacheTab([Parameter(Mandatory)] [System.Windows.Forms.TabPage]$HostTab) {
	$t = $HostTab
	$t.Controls.Clear()
	# ---- layout: main container ----
	$panelMain = $script:CacheWatcherDetailsPanel = New-Object Windows.Forms.Panel; $panelMain.Dock = 'Fill'
	$t.Controls.Add($panelMain)
	# list panel (center)
	$panelList = New-Object Windows.Forms.Panel; $panelList.Dock = 'Fill'
	$panelMain.Controls.Add($panelList)
	# bottom panel: clear cache button
	$panelBottom = New-Object Windows.Forms.Panel; $panelBottom.Dock = 'Bottom'; $panelBottom.Height = 40
	$panelMain.Controls.Add($panelBottom)
	# info panel (line 3)
	$panelTop = New-Object Windows.Forms.Panel; $panelTop.Dock = 'Top'; $panelTop.Height = 40
	$panelMain.Controls.Add($panelTop)
	# watcher panel (line 2)
	$panelWatcher = $script:CacheWatcherPanel = New-Object Windows.Forms.Panel; $panelWatcher.Dock = 'Top'; $panelWatcher.Height = 40
	$panelMain.Controls.Add($panelWatcher)
	# status panel (line 1)
	$panelStatus = $script:CacheStatusPanel = New-Object Windows.Forms.Panel; $panelStatus.Dock = 'Top'; $panelStatus.Height = 30
	$panelMain.Controls.Add($panelStatus)
	$lblWatcher = $script:CacheWatcherStatusLabel = New-Object Windows.Forms.Label; $lblWatcher.Left = 4; $lblWatcher.Top = 12; $lblWatcher.AutoSize = $true
	$panelStatus.Controls.Add($lblWatcher)
	# watcher row: label left, toggle/live/refresh right
	$flowWatcherLeft = New-Object Windows.Forms.FlowLayoutPanel; $flowWatcherLeft.Dock = 'Left'; $flowWatcherLeft.AutoSize = $true; $flowWatcherLeft.AutoSizeMode = 'GrowAndShrink'; $flowWatcherLeft.WrapContents = $false; $flowWatcherLeft.Padding = '0,2,4,4'
	$flowWatcherRight = New-Object Windows.Forms.FlowLayoutPanel; $flowWatcherRight.Dock = 'Right'; $flowWatcherRight.AutoSize = $true; $flowWatcherRight.AutoSizeMode = 'GrowAndShrink'; $flowWatcherRight.WrapContents = $false; $flowWatcherRight.Padding = '4,2,0,0'; $flowWatcherRight.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
	# Start button (with UAC shield)
	$btnStart = $script:CacheWatcherStartButton = New-Object Windows.Forms.Button; $btnStart.Text = (T 'button.cache_watcher_start'); $btnStart.AutoSize = $true; $btnStart.AutoSizeMode = 'GrowAndShrink'; $btnStart.MinimumSize = New-Object System.Drawing.Size(0, $script:ButtonXH); $btnStart.Margin = New-Object System.Windows.Forms.Padding(4,0,0,0)
	try { $null = $btnStart.Handle; Enable-FlatUacShield $btnStart } catch {} # start needs elevation
	# Stop button (no UAC shield)
	$btnStop = $script:CacheWatcherStopButton = New-Object Windows.Forms.Button; $btnStop.Text = (T 'button.cache_watcher_stop'); $btnStop.AutoSize = $true; $btnStop.AutoSizeMode = 'GrowAndShrink'; $btnStop.MinimumSize = New-Object System.Drawing.Size(0, $script:ButtonH); $btnStop.Margin = New-Object System.Windows.Forms.Padding(4,4,0,0)
	$chkLive = $script:CacheWatcherLiveCheckbox = New-Object Windows.Forms.CheckBox; $chkLive.Text = (T 'box.cache_live_update'); $chkLive.AutoSize = $true; $chkLive.Checked = $script:CacheWatcherLiveUpdate; $chkLive.Margin = New-Object System.Windows.Forms.Padding(0,10,4,0)
	$btnRefresh = $script:ButtonCacheRefresh = New-Object Windows.Forms.Button; $btnRefresh.Text = (T 'button.refresh'); $btnRefresh.Width = 100; $btnRefresh.Height = $script:ButtonH; $btnRefresh.Margin = New-Object System.Windows.Forms.Padding(4,4,0,0)
	$flowWatcherLeft.Controls.AddRange(@($btnStart, $btnStop))
	$flowWatcherRight.Controls.AddRange(@($btnRefresh, $chkLive))
	$panelWatcher.Controls.AddRange(@($flowWatcherLeft, $flowWatcherRight))
	# info row (line 3): only text on the left
	$lblInfo = $script:LabelCacheInfo = New-Object Windows.Forms.Label; $lblInfo.Text = (T 'label.cache_info' @{ size = (Format-CacheBytes 0) }); $lblInfo.Font = New-Object System.Drawing.Font($UiFontFamily, 9, $UiFontStyleRegular); $lblInfo.AutoSize = $true; $lblInfo.Left = 0; $lblInfo.Top = 8
	$panelTop.Controls.Add($lblInfo)
	# ListView
	$lv = $script:CacheListView = New-Object Windows.Forms.ListView; $lv.View = 'Details'; $lv.FullRowSelect = $true; $lv.MultiSelect = $true; $lv.HideSelection = $false; $lv.Dock = 'Fill'; $lv.HeaderStyle = 'Clickable'; $lv.GridLines = $true; $lv.Sorting = 'None'
	$lv.TabStop = $false; $lv.Enabled = $false; $lv.OwnerDraw = $true
	# Use smaller monospace font for cache entries
	$script:CacheListEntryFont = New-Object System.Drawing.Font('Consolas', 7.5)
	$lv.add_DrawColumnHeader({
		param($s,$e)
		$font = $e.Font
		$flags = [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter
		$e.Graphics.FillRectangle([System.Drawing.Brushes]::Gainsboro, $e.Bounds) # Paint header background (no DrawBackground)
		[System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.Header.Text, $font, $e.Bounds, [System.Drawing.SystemColors]::WindowText, $flags)
	})
	$lv.add_DrawItem({ param($s,$e) }) # required when OwnerDraw is true in Details view
	$lv.add_DrawSubItem({
		param($s,$e)
		$font = if ($script:CacheListEntryFont) { $script:CacheListEntryFont } else { $e.SubItem.Font }
		$flags = [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter
		# Always paint our own background (no DrawBackground)
		if (($e.ItemIndex % 2) -eq 1) { $e.Graphics.FillRectangle([System.Drawing.Brushes]::Honeydew, $e.Bounds) } else { $e.Graphics.FillRectangle([System.Drawing.SystemBrushes]::Window, $e.Bounds) }
		$textColor = [System.Drawing.SystemColors]::WindowText # Stable text color, independent of Selected/Focus
		[System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $e.SubItem.Text, $font, $e.Bounds, $textColor, $flags)
	})
	[void]$lv.Columns.Add((T 'column.cache_name'), 330); [void]$lv.Columns.Add((T 'column.cache_size'), 85); [void]$lv.Columns.Add((T 'column.cache_modified'), 131); [void]$lv.Columns.Add((T 'column.cache_type'), 55)
	# Make columns fill the full client width (avoid horizontal scrolling, full-row background)
	$script:AlignCacheColumns = {
		if (-not $script:CacheListView -or $script:CacheListView.IsDisposed) { return }
		$lvLocal = $script:CacheListView
		if ($lvLocal.Columns.Count -lt 4) { return }
		$w0 = 330; $w1 = 85; $w2 = 131 # Base widths for first three columns
		$total = $lvLocal.ClientSize.Width
		$last = [Math]::Max(40, $total - ($w0 + $w1 + $w2))
		$lvLocal.Columns[0].Width = $w0; $lvLocal.Columns[1].Width = $w1; $lvLocal.Columns[2].Width = $w2; $lvLocal.Columns[3].Width = $last
	}
	# Initial alignment
	if ($script:AlignCacheColumns -is [scriptblock]) { & $script:AlignCacheColumns }
	# Re-align when the ListView is resized
	$lv.add_Resize({ if ($script:AlignCacheColumns -is [scriptblock]) { & $script:AlignCacheColumns } })
	$panelList.Controls.Add($lv)
	# Bottom panel: right actions (clear cache + clear-on-exit)
	$flowRight = New-Object Windows.Forms.FlowLayoutPanel; $flowRight.Dock = 'Right'; $flowRight.AutoSize = $true; $flowRight.AutoSizeMode = 'GrowAndShrink'; $flowRight.WrapContents = $false; $flowRight.Padding = '4,4,0,4'; $flowRight.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
	$script:CacheClearOnExit = $true; try { $script:CacheClearOnExit = Get-CacheWatcherClearOnExit } catch {}
	$chkClearOnExit = $script:CacheClearOnExitCheckbox = New-Object Windows.Forms.CheckBox; $chkClearOnExit.Text = (T 'box.cache_clear_on_exit'); $chkClearOnExit.AutoSize = $true; $chkClearOnExit.Checked = $script:CacheClearOnExit; $chkClearOnExit.Margin = New-Object System.Windows.Forms.Padding(0,10,4,0)
	$btnDeleteAll = $script:ButtonCacheDeleteAll = New-Object Windows.Forms.Button; $btnDeleteAll.Text = (T 'button.clear_cache'); $btnDeleteAll.Width = 140; $btnDeleteAll.Height = $script:ButtonH
	$flowRight.Controls.AddRange(@($chkClearOnExit, $btnDeleteAll))
	$panelBottom.Controls.Add($flowRight)
	# ---- shared state + helpers ----
	$script:CacheEntries = @()
	$script:CacheSortColumn = 0
	$script:CacheSortDescending = $false
	$script:UpdateCacheTotalLabel = {
		if (-not $script:LabelCacheInfo -or $script:LabelCacheInfo.IsDisposed) { return }
		$total = 0L
		if ($script:CacheEntries) { foreach ($e in $script:CacheEntries) { $total += [int64]$e.Length } }
		$script:LabelCacheInfo.Text = (T 'label.cache_info' @{ size = (Format-CacheBytes($total)) })
	}
	$script:RenderCacheEntries = {
		if (-not $script:CacheListView -or $script:CacheListView.IsDisposed) { return }
		$entries = $script:CacheEntries
		if (-not $entries) {
			$script:CacheListView.BeginUpdate()
			$script:CacheListView.Items.Clear()
			$script:CacheListView.EndUpdate()
			if ($script:UpdateCacheTotalLabel -is [scriptblock]) { & $script:UpdateCacheTotalLabel }
			return
		}
		$items = $entries
		switch ($script:CacheSortColumn) {
			0 { $items = if ($script:CacheSortDescending) { $entries | Sort-Object Name -Descending } else { $entries | Sort-Object Name } }
			1 { $items = if ($script:CacheSortDescending) { $entries | Sort-Object Length -Descending } else { $entries | Sort-Object Length } }
			2 { $items = if ($script:CacheSortDescending) { $entries | Sort-Object LastWriteTimeUtc -Descending } else { $entries | Sort-Object LastWriteTimeUtc } }
			3 { $items = if ($script:CacheSortDescending) { $entries | Sort-Object Type -Descending } else { $entries | Sort-Object Type } }
		}
		$script:CacheListView.BeginUpdate()
		$script:CacheListView.Items.Clear()
		foreach ($f in $items) {
			$sizeText = Format-CacheBytes ([long]$f.Length)
			$dt = [DateTime]::SpecifyKind($f.LastWriteTimeUtc, [DateTimeKind]::Utc).ToLocalTime()
			$item = New-Object Windows.Forms.ListViewItem $f.Name
			[void]$item.SubItems.Add($sizeText)
			[void]$item.SubItems.Add($dt.ToString('yyyy-MM-dd HH:mm'))
			$typeText = if ($f.Type) { [string]$f.Type } else { 'file' }
			[void]$item.SubItems.Add($typeText)
			$item.Tag = $f
			[void]$script:CacheListView.Items.Add($item)
		}
		$script:CacheListView.EndUpdate()
		if ($script:UpdateCacheTotalLabel -is [scriptblock]) { & $script:UpdateCacheTotalLabel }
	}
	$script:RefreshCacheList = {
		try {
			if (-not $script:CacheListView -or $script:CacheListView.IsDisposed) { return $false }
			Write-Verbose "[CacheTab] RefreshCacheList: using Get-CacheAgentState"
			$state = Get-CacheAgentState
			# No snapshot: clear once when transitioning from "had snapshot" -> "no snapshot"
			if (-not $state -or -not $state.Snapshot) {
				Write-Verbose "[CacheTab] RefreshCacheList: no snapshot"
				if ($script:LastCacheSnapshotSignature -ne $null) {
					Write-Verbose "[CacheTab] RefreshCacheList: snapshot disappeared, clearing list once"
					$script:LastCacheSnapshotSignature = $null; $script:CacheEntries = @()
					if ($script:RenderCacheEntries -is [scriptblock]) { & $script:RenderCacheEntries }
				}
				else { Write-Verbose "[CacheTab] RefreshCacheList: snapshot still missing, list already cleared, skipping redraw" }
				return $false
			}
			# Snapshot present: build a cheap signature to detect changes
			$snapshot = $state.Snapshot
			$signature = "{0}|{1}|{2}|{3}" -f $snapshot.FileCount, $snapshot.TotalBytes, $snapshot.NewestWriteTimeUtc, $snapshot.OldestWriteTimeUtc
			if (-not $script:CacheForceRefreshOnce -and $signature -eq $script:LastCacheSnapshotSignature) { Write-Verbose "[CacheTab] RefreshCacheList: snapshot unchanged, skipping redraw"; return $true }
			# Either forced or snapshot changed: reset force flag and update signature
			$script:CacheForceRefreshOnce = $false
			$script:LastCacheSnapshotSignature = $signature
			$files = $snapshot.Files
			if (-not $files) { $script:CacheEntries = @(); if ($script:RenderCacheEntries -is [scriptblock]) { & $script:RenderCacheEntries }; return $true }
			$script:CacheEntries = @($files)
			if ($script:RenderCacheEntries -is [scriptblock]) { & $script:RenderCacheEntries }
			Write-Verbose ("[CacheTab] RefreshCacheList: rendered {0} items" -f $script:CacheListView.Items.Count)
			return $true
		} catch { try { $script:CacheListView.EndUpdate() } catch {}; Write-Verbose ("[CacheTab] RefreshCacheList error: {0}" -f $_.Exception.Message); return $false }
	}
	$script:UpdateCacheWatcherUi = {
		try {
			if (-not $script:CacheWatcherStatusLabel -or $script:CacheWatcherStatusLabel.IsDisposed) { return }
			if (-not $script:CacheWatcherStartButton -or $script:CacheWatcherStartButton.IsDisposed) { return }
			if (-not $script:CacheWatcherStopButton -or $script:CacheWatcherStopButton.IsDisposed) { return }
			$anyWatcher = $script:CacheWatcherPresent
			$starting = $script:CacheStartPending
			$stopping = $script:CacheStopPending
			$statusKey = 'label.cache_watcher_stopped'
			Write-Verbose ("[CacheTab] UpdateCacheWatcherUi: anyWatcher={0}, starting={1}, stopping={2}" -f $anyWatcher, $starting, $stopping)
			if ($starting -and -not $anyWatcher) {
				# starting (no watcher visible yet, start requested)
				$statusKey = 'status.starting'
				$script:CacheWatcherStartButton.Visible = $true
				$script:CacheWatcherStartButton.Enabled = $false
				$script:CacheWatcherStopButton.Visible = $false
			}
			elseif ($stopping -and $anyWatcher) {
				# stopping (stop requested, watcher still present)
				$statusKey = 'status.stopping'
				$script:CacheWatcherStartButton.Visible = $false
				$script:CacheWatcherStopButton.Visible = $true
				$script:CacheWatcherStopButton.Enabled = $false
			}
			elseif ($anyWatcher) {
				# running (normal state)
				$statusKey = 'status.running'
				$script:CacheWatcherStartButton.Visible = $false
				$script:CacheWatcherStopButton.Visible = $true
				$script:CacheWatcherStopButton.Enabled = $true
			}
			else {
				# stopped (no watcher, no pending start/stop)
				$statusKey = 'status.stopped'
				$script:CacheWatcherStartButton.Visible = $true
				$script:CacheWatcherStartButton.Enabled = $true
				$script:CacheWatcherStopButton.Visible = $false
			}
			Write-Verbose ("[CacheTab] UpdateCacheWatcherUi: statusKey={0}" -f $statusKey)
			$script:CacheWatcherStatusLabel.Text = (T 'label.cache_watcher_status' @{ status = (T $statusKey) })
			# disable details while stopping, otherwise coupled to watcher presence
			$detailsEnabled = $anyWatcher -and -not $stopping
			if ($script:LabelCacheInfo -and -not $script:LabelCacheInfo.IsDisposed) { $script:LabelCacheInfo.Enabled = $detailsEnabled }
			if ($script:CacheListView -and -not $script:CacheListView.IsDisposed) { $script:CacheListView.Enabled = $detailsEnabled }
			if ($script:ButtonCacheDeleteAll -and -not $script:ButtonCacheDeleteAll.IsDisposed) { $script:ButtonCacheDeleteAll.Enabled = $detailsEnabled }
			if ($script:ButtonCacheRefresh -and -not $script:ButtonCacheRefresh.IsDisposed) { $script:ButtonCacheRefresh.Enabled = $detailsEnabled }
			if ($script:CacheWatcherLiveCheckbox -and -not $script:CacheWatcherLiveCheckbox.IsDisposed) { $script:CacheWatcherLiveCheckbox.Enabled = $detailsEnabled }
			if ($script:CacheClearOnExitCheckbox -and -not $script:CacheClearOnExitCheckbox.IsDisposed) { $script:CacheClearOnExitCheckbox.Enabled = $detailsEnabled }
		} catch { Write-Verbose ("[CacheTab] UpdateCacheWatcherUi: ERROR {0}" -f $_.Exception.Message) }
	}
	$script:InvokeCacheDeleteAll = {
		if (-not $script:CacheWatcherPresent) { return }
		$ans = Ask-YesNoWarnT 'prompt.cache_delete_all_confirm'
		if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return }
		if (Request-CacheDeleteAll) {
			$script:CacheListView.Items.Clear()
			$script:CacheEntries = @()
			if ($script:UpdateCacheTotalLabel -is [scriptblock]) { & $script:UpdateCacheTotalLabel }
		}
	}
	$script:InvokeCacheRefresh = { $script:CacheForceRefreshOnce = $true; if ($script:RefreshCacheList -is [scriptblock]) { [void](& $script:RefreshCacheList) } }
	if (-not $script:CacheAgentTimer) {
		$script:CacheAgentTimer = New-Object System.Windows.Forms.Timer
		$script:CacheAgentTimer.Interval = 1000 # 1500
		$script:CacheAgentTimer.Add_Tick({
			try {
				# Always pull live PIDs (this also cleans orphaned ones)
				Write-Verbose "[CacheTab] Timer tick: querying watcher entries"
				$watchersRaw = Get-CacheWatcherEntries
				$watchers = @()
				if ($watchersRaw) { $watchers = @($watchersRaw) } # Normalize to an array, even if a single PSCustomObject is returned
				$count = $watchers.Count
				$anyWatcher = ($count -gt 0)
				Write-Verbose ("[CacheTab] Timer tick: watchers.Count={0}, anyWatcher={1}" -f $count, $anyWatcher)
				$script:CacheWatcherPresent = $anyWatcher
				if ($anyWatcher -and $script:CacheClearOnExitCheckbox -and -not $script:CacheClearOnExitCheckbox.IsDisposed) {
					try { $flag = Get-CacheWatcherClearOnExit; if ($flag -ne $script:CacheClearOnExit) { $script:CacheClearOnExit = $flag; $script:CacheClearOnExitCheckbox.Checked = $flag } } catch {}
				}
				# Transition: starting -> running
				if ($anyWatcher -and $script:CacheStartPending) { Write-Verbose "[CacheTab] Timer tick: watcher detected, clearing CacheStartPending"; $script:CacheStartPending = $false }
				# Transition: stopping -> stopped
				if (-not $anyWatcher -and $script:CacheStopPending) { Write-Verbose "[CacheTab] Timer tick: no watcher, clearing CacheStopPending"; $script:CacheStopPending = $false }
				# When no watcher and no start pending: full reset of UI list
				if (-not $anyWatcher -and -not $script:CacheStartPending) {
					Write-Verbose "[CacheTab] Timer tick: no watcher and no start pending, clearing list"
					if ($script:CacheListView -and -not $script:CacheListView.IsDisposed) { $script:CacheListView.BeginUpdate(); $script:CacheListView.Items.Clear(); $script:CacheListView.EndUpdate() }
					$script:CacheEntries = @()
					if ($script:UpdateCacheTotalLabel -is [scriptblock]) { & $script:UpdateCacheTotalLabel }
				}
				if ($script:UpdateCacheWatcherUi -is [scriptblock]) { & $script:UpdateCacheWatcherUi }
				if ($script:CacheWatcherLiveUpdate -and $script:RefreshCacheList -is [scriptblock] -and $script:CacheWatcherPresent) { Write-Verbose "[CacheTab] Timer tick: live update enabled, refreshing cache list"; [void](& $script:RefreshCacheList) }
			} catch { Write-Verbose ("[CacheTab] Timer tick: ERROR {0}" -f $_.Exception.Message) }
		})
	}
	$t.Add_Enter({ if ($script:CacheAgentTimer) { $script:CacheAgentTimer.Enabled = $true }; if ($script:RefreshCacheList -is [scriptblock]) { [void](& $script:RefreshCacheList) } })
	# ---- wiring ----
	$chkClearOnExit.Add_CheckedChanged({ $script:CacheClearOnExit = $this.Checked; if ($script:CacheWatcherPresent) { try { Set-CacheWatcherClearOnExit -value $script:CacheClearOnExit } catch {} } })
	$btnRefresh.Add_Click({ & $script:InvokeCacheRefresh })
	$btnDeleteAll.Add_Click({ & $script:InvokeCacheDeleteAll })
	$lv.add_ColumnClick({
		param($s, $e)
		$col = [int]$e.Column
		if ($col -eq $script:CacheSortColumn) { $script:CacheSortDescending = -not $script:CacheSortDescending } else { $script:CacheSortColumn = $col; $script:CacheSortDescending = $false }
		if ($script:RenderCacheEntries -is [scriptblock]) { & $script:RenderCacheEntries }
	})
	# wiring for watcher controls: Start (with UAC shield) / Stop (no shield)
	$script:CacheWatcherStartButton.Add_Click({
		if ($script:CacheWatcherPresent) { return }
		if (Start-CacheWatcher) { $script:CacheStopPending = $false; $script:CacheStartPending = $true; try { Set-CacheWatcherClearOnExit -value $script:CacheClearOnExit } catch {}; if ($script:UpdateCacheWatcherUi -is [scriptblock]) { & $script:UpdateCacheWatcherUi } } else { Show-ErrorT 'message.uac_admin_required' }
	})
	$script:CacheWatcherStopButton.Add_Click({
		if (-not $script:CacheWatcherPresent) { return }
		# Only warn if watcher is configured to clear cache on automatic exit
		if (Get-CacheWatcherClearOnExit) { $ans = (Ask-YesNoWarnT 'prompt.cache_watcher_stop_warn' @{ cache_clear_on_exit = (T 'box.cache_clear_on_exit') }); if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) { return } }
		try { $null = Send-CacheAgentCommand @{ Action = 'Stop' } } catch {}
		$script:CacheStopPending = $true
		if ($script:UpdateCacheWatcherUi -is [scriptblock]) { & $script:UpdateCacheWatcherUi }
	})
	$chkLive.Add_CheckedChanged({ $script:CacheWatcherLiveUpdate = $this.Checked }) # Timer always stays on; only the behavior during the tick changes.
	if ($script:UpdateCacheWatcherUi -is [scriptblock]) { & $script:UpdateCacheWatcherUi }
}
