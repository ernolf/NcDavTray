# Up to 1.2.2 the drive icon was cached in a single server_favicon.ico, which is
# not read any more. Deleting it is idempotent and needs no completion flag: the
# absence of the file is what stops the cleanup.
function Remove-LegacyFavIcon {
	$legacy = Join-Path $HereDir 'server_favicon.ico'
	if (Test-Path -LiteralPath $legacy) { try { Remove-Item -LiteralPath $legacy -Force } catch {} }
}
