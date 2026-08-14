# Join two subpath fragments using forward slashes and normalize the result
function Join-SubPath([string]$base, [string]$child) { $base = Normalize-SubPath $base; $child = Normalize-SubPath $child; if ([string]::IsNullOrWhiteSpace($base)) { return $child }; if ([string]::IsNullOrWhiteSpace($child)) { return $base }; return ($base + '/' + $child) }
