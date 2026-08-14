# Basic auth header for HttpWebRequest
function New-BasicAuthHeader([string]$user, [string]$pass) { 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$user`:$pass")) }
