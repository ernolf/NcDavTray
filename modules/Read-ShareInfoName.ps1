# The name shareinfo gives the shared file or folder, or '' when the answer does
# not name one. That name is what a share is called where its owner gave it none,
# and it is the only name a protected share hands out at all -- the share page,
# which carries the label, answers with its login form instead.
# Only the top level is of interest: a shared folder lists its children under the
# same property name.
function Read-ShareInfoName {
	[CmdletBinding()] param( [Parameter(Mandatory)][System.Net.WebResponse]$Response )
	$json = $null
	try {
		$reader = New-Object System.IO.StreamReader($Response.GetResponseStream(), [System.Text.Encoding]::UTF8)
		try { $json = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
	} catch { return '' }
	if (-not $json -or ($json.PSObject.Properties.Name -notcontains 'data')) { return '' }
	$data = $json.data
	if (-not $data -or ($data.PSObject.Properties.Name -notcontains 'name')) { return '' }
	return ([string]$data.name).Trim()
}
