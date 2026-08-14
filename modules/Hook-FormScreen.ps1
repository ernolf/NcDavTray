# Windows centres a window on the primary display. On a desk with three of them
# that is not where the user is: a password prompt two screens away reads as a
# program that did nothing, and the answer it waits for never comes. The pointer
# is where the work is, so its screen is where the window belongs.
# The decision is made at Load, where the window has its final size and has
# already said where it wanted to go. A window that asked for CenterParent is
# left alone: its parent is on the screen in use, which is the same answer.
function Hook-FormScreen([System.Windows.Forms.Form]$f) {
	if (-not $f) { return }
	$f.add_Load({
			if ($this.StartPosition -ne [System.Windows.Forms.FormStartPosition]::CenterScreen) { return }
			try {
				$area = [System.Windows.Forms.Screen]::FromPoint([System.Windows.Forms.Cursor]::Position).WorkingArea
				# A window larger than the screen starts in its corner: what hangs off
				# the far edge can still be reached, what hangs off the near one cannot.
				$x = [Math]::Max($area.X, $area.X + [int](($area.Width - $this.Width) / 2))
				$y = [Math]::Max($area.Y, $area.Y + [int](($area.Height - $this.Height) / 2))
				$this.Location = New-Object System.Drawing.Point($x, $y)
			} catch {}
		})
}