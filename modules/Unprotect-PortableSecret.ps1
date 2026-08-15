# Reads a secret file of either generation and hands back its plaintext together
# with the tag it carried, because what that plaintext means depends on it.
# A wrong passphrase surfaces as a padding error out of TransformFinalBlock, and
# it is thrown rather than swallowed: the caller has to tell "wrong passphrase"
# from "no file", and only one of the two is worth asking again about.
function Unprotect-PortableSecret {
	[CmdletBinding()] param( [Parameter(Mandatory)][string]$Passphrase, [Parameter(Mandatory)][string]$Path )
	$blob = [System.IO.File]::ReadAllBytes($Path)
	if ($blob.Length -lt 41) { throw 'Secret file is corrupt.' }
	$tag = [System.Text.Encoding]::ASCII.GetString($blob, 0, 5)
	if ($tag -notin @('NCPT1', 'NCPT2')) { throw 'Secret file format not recognized.' }
	$salt = New-Object byte[] 16; [Array]::Copy($blob, 5, $salt, 0, 16)
	$iv = New-Object byte[] 16; [Array]::Copy($blob, 21, $iv, 0, 16)
	$lenB = New-Object byte[] 4; [Array]::Copy($blob, 37, $lenB, 0, 4)
	$clen = [BitConverter]::ToInt32($lenB, 0)
	if ($clen -lt 0 -or ($clen + 41) -gt $blob.Length) { throw 'Secret file is corrupt.' }
	$cipher = New-Object byte[] $clen; [Array]::Copy($blob, 41, $cipher, 0, $clen)
	$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 100000)
	$key = $kdf.GetBytes(32)
	$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.KeySize = 256; $aes.Key = $key; $aes.IV = $iv
	$dec = $aes.CreateDecryptor()
	try { $plainBytes = $dec.TransformFinalBlock($cipher, 0, $cipher.Length) }
	finally { $dec.Dispose(); $aes.Dispose(); $kdf.Dispose() }
	return [pscustomobject]@{ Format = $tag; Text = [System.Text.Encoding]::UTF8.GetString($plainBytes) }
}