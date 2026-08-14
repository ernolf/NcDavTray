# Compute SHA1 hex for stable mutex names
function Get-Sha1Hex([Parameter(Mandatory = $true)][string]$Text) { $sha1 = [System.Security.Cryptography.SHA1]::Create(); $bytes = [Text.Encoding]::UTF8.GetBytes($Text); $hash = $sha1.ComputeHash($bytes); return (($hash | ForEach-Object { $_.ToString('x2') }) -join '') }
