function Fetch-UserAvatar([string]$server, [string]$user) {
	if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($user)) { return $null }
	# A user ID may hold spaces and other characters that are not legal in a path
	# segment, so it is encoded before it becomes one.
	$base = "https://$server/index.php/avatar/$([Uri]::EscapeDataString($user))/64?guestFallback=1"
	$bmp = Get-HttpImage -url $base -timeoutMs 3000
	if ($bmp) { if ($script:UserAvatarBmp) { try { $script:UserAvatarBmp.Dispose() } catch {} }; $script:UserAvatarBmp = $bmp }
	return $bmp
}
