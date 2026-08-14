# Encode path for OCS API ('' -> '', 'A/B' -> 'A%2FB')
function Encode-OcsPath([string]$path) { $norm = Normalize-SubPath $path; if ([string]::IsNullOrWhiteSpace($norm)) { return '' }; return [Uri]::EscapeDataString($norm) }
