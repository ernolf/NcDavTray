# What the project page says the newest release is. Nothing asks for this on its
# own: it runs when the About box is told to, or once after start when that was
# switched on -- a program that phones home unasked is one nobody asked to.
# The address is derived from $ProjectUrl, so what the updater looks at is the
# release the About box links to and not a second address that can drift.
function Get-UpdateInfo {
	[CmdletBinding()] param([int]$TimeoutMs = 6000)
	$fail = [pscustomobject]@{ Ok = $false; Tag = ''; Version = $null; Newer = $false; AssetUrl = ''; AssetSize = 0 }
	$repo = [regex]::Match([string]$ProjectUrl, '^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$')
	if (-not $repo.Success) { return $fail }
	$uri = 'https://api.github.com/repos/{0}/{1}/releases/latest' -f $repo.Groups[1].Value, $repo.Groups[2].Value
	$raw = $null
	try {
		$req = New-HttpGetRequest $uri $TimeoutMs 'application/vnd.github+json'
		$resp = $req.GetResponse()
		try {
			$sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
			$raw = $sr.ReadToEnd()
			$sr.Close()
		} finally { try { $resp.Close() } catch {} }
	} catch { return $fail }
	$j = $null
	try { $j = $raw | ConvertFrom-Json } catch { return $fail }
	if (-not $j -or -not ($j.PSObject.Properties.Name -contains 'tag_name')) { return $fail }
	$tag = [string]$j.tag_name
	# A tag that is not a version number is still an answer: it says what the newest
	# release is called. What it does not say is whether that release is ahead of
	# this copy, and guessing at that would either nag or hide an update.
	$ver = $null
	$m = [regex]::Match($tag, '^v?(\d+)\.(\d+)(?:\.(\d+))?$')
	if ($m.Success) {
		$build = if ($m.Groups[3].Success) { [int]$m.Groups[3].Value } else { 0 }
		$ver = New-Object System.Version([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, $build)
	}
	# Strictly ahead, never merely different: between two releases this copy is the
	# newer one, and telling its user to install what it already is past is worse
	# than saying nothing.
	$newer = $false
	if ($ver) { try { $newer = ($ver -gt [version]$Version) } catch {} }
	# The archive the release workflow attaches, looked up by the name it is built
	# under rather than by taking whatever file happens to hang on the release --
	# something added there by hand is not what this offers to install. A release
	# without it is still an answer: it says a newer version exists, and the way to
	# it is the project page.
	$url = ''; $size = 0
	$want = '{0}_v{1}.zip' -f $AppName, ($tag -replace '^v', '')
	if ($j.PSObject.Properties.Name -contains 'assets') {
		foreach ($a in @($j.assets)) {
			if (([string]$a.name) -ieq $want) { $url = [string]$a.browser_download_url; try { $size = [int64]$a.size } catch { $size = 0 }; break }
		}
	}
	return [pscustomobject]@{ Ok = $true; Tag = $tag; Version = $ver; Newer = $newer; AssetUrl = $url; AssetSize = $size }
}