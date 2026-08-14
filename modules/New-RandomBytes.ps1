# Cryptographic random, not [Random]: salt and IV are the two values the strength
# of the container rests on.
function New-RandomBytes([int]$n) {
	$bytes = New-Object byte[] $n
	[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
	return $bytes
}