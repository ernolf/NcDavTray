# Writes the secret file: AES-256 in CBC mode with PKCS7 padding, the key derived
# from the passphrase with PBKDF2 (100,000 rounds), salt and IV 16 random bytes
# each. The layout is the one the versions before 2.0.0 wrote, tag included --
# 5 byte tag, 16 salt, 16 IV, 4 byte length, ciphertext.
# The tag says what the plaintext is: NCPT1 held the one password such a version
# could have, NCPT2 holds the table of all of them. Nothing else distinguishes
# the two, and a reader that guessed would guess wrong on a password shaped like
# json.
function Protect-PortableSecret {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Plain, [Parameter(Mandatory)][string]$Passphrase, [Parameter(Mandatory)][string]$Path )
	if ([string]::IsNullOrEmpty($Plain) -or [string]::IsNullOrEmpty($Passphrase)) { throw 'Missing content or passphrase.' }
	$salt = New-RandomBytes 16
	$iv = New-RandomBytes 16
	$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 100000)
	$key = $kdf.GetBytes(32)
	$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.KeySize = 256; $aes.Key = $key; $aes.IV = $iv
	$enc = $aes.CreateEncryptor()
	$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
	$cipher = $enc.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
	$enc.Dispose(); $aes.Dispose(); $kdf.Dispose()
	$head = [System.Text.Encoding]::ASCII.GetBytes('NCPT2')
	$len = [BitConverter]::GetBytes([int]$cipher.Length)
	$blob = New-Object byte[] ($head.Length + 16 + 16 + 4 + $cipher.Length)
	[Array]::Copy($head, 0, $blob, 0, $head.Length)
	[Array]::Copy($salt, 0, $blob, $head.Length, 16)
	[Array]::Copy($iv, 0, $blob, $head.Length + 16, 16)
	[Array]::Copy($len, 0, $blob, $head.Length + 32, 4)
	[Array]::Copy($cipher, 0, $blob, $head.Length + 36, $cipher.Length)
	[System.IO.File]::WriteAllBytes($Path, $blob)
}