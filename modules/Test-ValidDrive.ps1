function Test-ValidDrive([string]$d) { (-not [string]::IsNullOrWhiteSpace($d)) -and ($d -match '^[A-Za-z]:$') }
