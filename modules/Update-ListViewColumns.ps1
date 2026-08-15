# Gives every column the width its longest entry needs -- its own header or the
# widest value under it, whichever asks for more. A width written down when the
# list is built is a width that is wrong in the next language and for the next
# server name.
# The text is measured here instead of leaving it to the list: LVSCW_AUTOSIZE
# reads the last column as "take whatever is left" and answers with the rest of
# the window, which is a width nothing in that column ever asked for.
function Update-ListViewColumns {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Windows.Forms.ListView]$ListView )
	if ($ListView.IsDisposed -or $ListView.Columns.Count -eq 0) { return }
	# What the header and the cells draw around their text.
	$pad = 8
	$font = $ListView.Font
	$total = 0
	foreach ($col in $ListView.Columns) {
		$width = [System.Windows.Forms.TextRenderer]::MeasureText($col.Text, $font).Width
		foreach ($item in $ListView.Items) {
			if ($col.Index -ge $item.SubItems.Count) { continue }
			$width = [Math]::Max($width, [System.Windows.Forms.TextRenderer]::MeasureText($item.SubItems[$col.Index].Text, $font).Width)
		}
		$col.Width = $width + $pad
		# An icon stands in front of the text of the first column and needs its own room
		if ($col.Index -eq 0 -and $ListView.SmallImageList) { $col.Width += $ListView.SmallImageList.ImageSize.Width + 4 }
		$total += $col.Width
	}
	# What is left over goes to the first column: a list that stops short of its own
	# right edge looks like it has lost a column.
	$room = $ListView.ClientSize.Width - $total
	if ($room -gt 0) { $ListView.Columns[0].Width += $room }
}