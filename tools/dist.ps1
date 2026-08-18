# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Packs the built product folder into the archive that is attached to a release.

	The archive contains the product folder itself, not its contents, so that
	unpacking anywhere produces one tidy directory. That is how the released
	archives have always been laid out and changing it would surprise everyone
	who updates by unpacking over their existing folder.

	Expects tools\build.ps1 to have run; use make.cmd, which sequences the two.

	Usage:
		tools\dist.ps1             pack build\NcDavTray
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildDir = Join-Path $RepoRoot 'build'

# Name and version of what is packed, both read from the single places that
# define them. The archive name is not ours alone: Get-UpdateInfo builds the
# name it looks for on a release out of the same two values, and an update it
# cannot find is an update that does not happen.
. (Join-Path $RepoRoot 'meta\AppName.ps1')
. (Join-Path $RepoRoot 'meta\Version.ps1')

$ProductDir = Join-Path $BuildDir $AppName

if (-not (Test-Path -LiteralPath $ProductDir -PathType Container)) {
	throw ("nothing to pack: {0} does not exist -- build first" -f $ProductDir)
}

$archive = Join-Path $BuildDir ("{0}_v{1}.zip" -f $AppName, $Version)
if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }

# ZipFile and ZipFileExtensions come from the first assembly, ZipArchive and
# ZipArchiveMode from the second.
Add-Type -AssemblyName System.IO.Compression.FileSystem
Add-Type -AssemblyName System.IO.Compression

# Entry by entry rather than CreateFromDirectory: that method writes the paths
# with backslashes on .NET Framework, and the zip format calls for forward
# slashes. Windows Explorer copes either way, but 7-Zip and unzip create files
# whose names literally contain a backslash. The released archives have always
# had forward slashes.
$root = Split-Path -Leaf $ProductDir
$base = (Resolve-Path -LiteralPath $ProductDir).Path.TrimEnd('\')
$zip = [System.IO.Compression.ZipFile]::Open($archive, [System.IO.Compression.ZipArchiveMode]::Create)
try {
	foreach ($f in (Get-ChildItem -LiteralPath $ProductDir -Recurse -File | Sort-Object FullName)) {
		$rel = $f.FullName.Substring($base.Length + 1) -replace '\\', '/'
		[void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
			$zip, $f.FullName, ("{0}/{1}" -f $root, $rel),
			[System.IO.Compression.CompressionLevel]::Optimal)
	}
} finally { $zip.Dispose() }

Write-Host ("packed   {0}  {1} bytes" -f (Split-Path -Leaf $archive), (Get-Item -LiteralPath $archive).Length)
