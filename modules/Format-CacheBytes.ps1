function Format-CacheBytes([long]$b) {
	if ($b -ge 1GB) { return ('{0:N1} GB' -f ($b / 1GB)) }
	elseif ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
	elseif ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
	else { return ('{0:N0} B' -f $b) }
}
