# returns raw bytes of embedded .ico # strip whitespace just in case
function Get-EmbeddedIconBytes { $b64 = ($LogoIcoB64 -replace '\s', ''); return [Convert]::FromBase64String($b64) }
