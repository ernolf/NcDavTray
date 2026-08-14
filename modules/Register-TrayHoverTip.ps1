# The tooltip Windows draws for a tray icon is read once, at the moment it opens:
# a status that changes while the pointer rests on the icon stays unseen until the
# user moves away and comes back. So the shell's tooltip is switched off -- the
# NotifyIcon.Text of a registered icon is kept empty -- and a small window of our
# own takes its place, in the colours and the font the system uses for tooltips.
# Set-TrayTipText holds the text it shows.
#
# A window rather than a WinForms ToolTip, because a tooltip belongs to a window
# and Windows decides on its own whether to draw it: with a dialog of ours in
# focus none appeared at all, and one that reached its display timeout vanished
# without telling us, leaving the state behind out of step. This window is shown
# once, off-screen, and from then on only moved -- so it never takes the focus,
# and it goes away when we move it away and not before.
#
# Hover ends without an event: NotifyIcon has MouseMove but no MouseLeave. So
# MouseMove only notes which icon the pointer went to and when, and a timer does
# the rest: it puts the tip up once the pointer has rested on the icon long
# enough, and takes it down the moment the pointer is
# outside the icon's rectangle. Without that rectangle -- the shell may decline to
# give it -- it falls back to timing out on the last MouseMove seen.
function Register-TrayHoverTip {
	[CmdletBinding()]
	param([System.Windows.Forms.NotifyIcon]$Notify)
	if (-not $Notify) { return }
	if (-not ($script:TrayTipTexts -is [hashtable])) { $script:TrayTipTexts = @{} }
	if (-not $script:TrayTipForm) {
		# Far enough out that no screen reaches it, which is where the window waits
		$script:TrayTipHome = New-Object System.Drawing.Point(-32000, -32000)
		$script:TrayTipForm = New-Object System.Windows.Forms.Form
		$script:TrayTipForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
		$script:TrayTipForm.ShowInTaskbar = $false
		$script:TrayTipForm.TopMost = $true
		$script:TrayTipForm.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
		$script:TrayTipForm.Location = $script:TrayTipHome
		$script:TrayTipForm.Font = [System.Drawing.SystemFonts]::StatusFont
		# The one pixel that shows around the label is the border of a tooltip
		$script:TrayTipForm.BackColor = [System.Drawing.SystemColors]::WindowFrame
		$script:TrayTipForm.Padding = New-Object System.Windows.Forms.Padding(1)
		$script:TrayTipLabel = New-Object System.Windows.Forms.Label
		$script:TrayTipLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
		$script:TrayTipLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
		$script:TrayTipLabel.BackColor = [System.Drawing.SystemColors]::Info
		$script:TrayTipLabel.ForeColor = [System.Drawing.SystemColors]::InfoText
		[void]$script:TrayTipForm.Controls.Add($script:TrayTipLabel)
		$script:TrayTipForm.Show()
		$script:TrayTipIcon = $null
		$script:TrayTipVisible = $false
		$script:TrayTipShown = ''
		$script:TrayTipSeen = [datetime]::MinValue
		$script:TrayTipSince = [datetime]::MaxValue
		$script:TrayTipRect = [System.Drawing.Rectangle]::Empty
		$script:TrayTipBlocked = $false
		# Milliseconds the pointer has to rest on the icon before the tip appears. The
		# system's own hover time (400 ms as a rule) reads as sluggish here, because a
		# tray icon is aimed at deliberately and not brushed past.
		$script:TrayTipDelay = 250
		# Over the icon the text is about, the way the shell places its own: its left
		# edge on the icon's, just above it, and pushed back in when the screen ends
		# before the text does. The pointer only says which icon is meant -- placing
		# against it made the tip land wherever the pointer had come in from.
		$script:TrayTipShow = {
			$text = if ($script:TrayTipIcon) { [string]$script:TrayTipTexts[$script:TrayTipIcon] } else { '' }
			if ([string]::IsNullOrEmpty($text)) { & $script:TrayTipHide; return }
			$script:TrayTipLabel.Text = $text
			$sz = [System.Windows.Forms.TextRenderer]::MeasureText($text, $script:TrayTipForm.Font)
			$script:TrayTipForm.ClientSize = New-Object System.Drawing.Size(($sz.Width + 12), ($sz.Height + 8))
			$w = $script:TrayTipForm.Width
			$h = $script:TrayTipForm.Height
			$rect = $script:TrayTipRect
			if ($rect.IsEmpty) {
				# The shell would not say where the icon is, so the pointer stands in for it
				$pos = [System.Windows.Forms.Cursor]::Position
				$rect = New-Object System.Drawing.Rectangle(($pos.X - 8), ($pos.Y - 8), 16, 16)
			}
			$area = [System.Windows.Forms.Screen]::FromRectangle($rect).Bounds
			$x = [Math]::Max($area.Left, [Math]::Min($rect.Left, ($area.Right - $w)))
			$y = $rect.Top - $h - 4
			# A taskbar at the top leaves no room above the icon
			if ($y -lt $area.Top) { $y = $rect.Bottom + 4 }
			$script:TrayTipForm.Location = New-Object System.Drawing.Point($x, $y)
			# The taskbar is topmost as well, and within that group the order decides --
			# ours was put there once at startup and has been sinking behind it since.
			# Setting the property again re-asserts it, and unlike BringToFront it does
			# not activate the window, so the focus stays where the user left it.
			$script:TrayTipForm.TopMost = $false
			$script:TrayTipForm.TopMost = $true
			$script:TrayTipVisible = $true
			$script:TrayTipShown = $text
		}
		$script:TrayTipHide = {
			if (-not $script:TrayTipVisible) { return }
			$script:TrayTipForm.Location = $script:TrayTipHome
			$script:TrayTipVisible = $false
			$script:TrayTipShown = ''
		}
		# Pointer watch: opens the hover, ends it, and follows a status that changed
		# under it. Short enough an interval that leaving the icon reads as immediate.
		$script:TrayTipWatch = New-Object System.Windows.Forms.Timer
		$script:TrayTipWatch.Interval = 50
		$script:TrayTipWatch.Add_Tick({
				if (-not $script:TrayTipIcon) { & $script:TrayTipHide; return }
				$gone = if ($script:TrayTipRect.IsEmpty) {
					((Get-Date) - $script:TrayTipSeen).TotalMilliseconds -gt 250
				} else {
					-not $script:TrayTipRect.Contains([System.Windows.Forms.Cursor]::Position)
				}
				if ($gone) {
					& $script:TrayTipHide
					$script:TrayTipIcon = $null
					$script:TrayTipBlocked = $false
					return
				}
				if ($script:TrayTipBlocked) { return }
				# A context menu of ours is closed by any window that shows itself over it
				$menu = $script:TrayTipIcon.ContextMenuStrip
				if ($menu -and $menu.Visible) { & $script:TrayTipHide; return }
				if (-not $script:TrayTipVisible) {
					if (((Get-Date) - $script:TrayTipSince).TotalMilliseconds -ge $script:TrayTipDelay) { & $script:TrayTipShow }
					return
				}
				if ([string]$script:TrayTipTexts[$script:TrayTipIcon] -ne $script:TrayTipShown) { & $script:TrayTipShow }
			})
		$script:TrayTipWatch.Start()
	}
	if (-not $script:TrayTipTexts.ContainsKey($Notify)) { $script:TrayTipTexts[$Notify] = '' }
	$Notify.Text = ''
	# Deliberately no GetNewClosure: inside one, $script: addresses the closure's
	# own module scope, and everything set up above would read as empty.
	$Notify.Add_MouseMove({
			param($s, $e)
			$script:TrayTipSeen = Get-Date
			# Nothing is shown from here -- the timer decides when the wait is over. The
			# icon's rectangle is worth asking the shell for only once per hover.
			if ($script:TrayTipIcon -ne $s) {
				& $script:TrayTipHide
				$script:TrayTipIcon = $s
				$script:TrayTipRect = [Nc.TrayIcon]::GetRect($s)
				$script:TrayTipSince = Get-Date
			}
		})
	# A click of any kind has the user's attention elsewhere -- and what it opens, the
	# context menu above all, must not be pushed away by a tip appearing a moment
	# later. So nothing more is shown until the pointer has left the icon.
	$Notify.Add_MouseDown({
			& $script:TrayTipHide
			$script:TrayTipBlocked = $true
		})
}