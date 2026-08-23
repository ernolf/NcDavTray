# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Freezes the current commit of main as the signed tag for the version in
	meta\Version.ps1 and pushes it.

	A tag is not moved afterwards, so everything that belongs in the release has
	to be merged first -- which is what the checks here are for: main, clean,
	in sync with origin, a changelog section for this version, and a version
	nobody has tagged yet.

	Publishing the release is the step after this one. release.yml then rebuilds
	from the tag, verifies that it matches meta\Version.ps1 and attaches the
	archive; that release is what installations out there see as an update.

	Usage:
		tools\tag.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ChangelogPath = Join-Path $RepoRoot 'CHANGELOG.md'

# The version to tag, and the project the release is published under -- both
# read from the single places that define them. ProjectUrl is the same value the
# update check derives its release address from, so the release is drafted where
# the installations will look for it.
. (Join-Path $RepoRoot 'meta\Version.ps1')
. (Join-Path $RepoRoot 'meta\ProjectUrl.ps1')

$tag = "v{0}" -f $Version

$branchNow = & git -C $RepoRoot rev-parse --abbrev-ref HEAD
if ($branchNow -ne 'main') { throw ("a release is tagged on main -- you are on '{0}'" -f $branchNow) }
if (@(& git -C $RepoRoot status --porcelain).Count -gt 0) {
	throw 'the working tree is not clean -- a tag must point at what was merged, nothing else'
}

& git -C $RepoRoot fetch --quiet origin main
if ($LASTEXITCODE -ne 0) { throw 'could not reach origin -- the tag has to be pushed, so this is not optional' }
if ((& git -C $RepoRoot rev-parse HEAD) -ne (& git -C $RepoRoot rev-parse origin/main)) {
	throw 'main is not what origin has -- git pull first'
}

& git -C $RepoRoot rev-parse -q --verify ("refs/tags/{0}" -f $tag) > $null
if ($LASTEXITCODE -eq 0) { throw ("{0} already exists -- a released tag is never moved" -f $tag) }

$latestTag = @(& git -C $RepoRoot tag --list 'v*' --sort=-v:refname) | Select-Object -First 1
$latest = if ($latestTag) { $latestTag.Substring(1) } else { '0.0.0' }
if ([version]$Version -le [version]$latest) {
	throw ("meta\Version.ps1 is {0}, which is not greater than the latest tag v{1} -- run make.cmd version first" -f $Version, $latest)
}

# The changelog is what a release is read from, and it cannot be added later:
# the tag is what release.yml builds from.
if (-not (Test-Path -LiteralPath $ChangelogPath)) { throw ("no {0}" -f $ChangelogPath) }
$changelog = [System.IO.File]::ReadAllText($ChangelogPath, [System.Text.UTF8Encoding]::new($false))
if ($changelog -notmatch ("(?m)^## \[{0}\]" -f [regex]::Escape($Version))) {
	throw ("CHANGELOG.md has no [{0}] section -- run make.cmd changelog and merge it first" -f $Version)
}

Write-Host '############################################################################'
Write-Host ("##  About to create and push the signed tag {0} at the current commit." -f $tag)
Write-Host '##  A tag is frozen: everything this release contains must be merged NOW.'
Write-Host '############################################################################'
Write-Host ("##  {0}" -f (& git -C $RepoRoot log -1 --pretty='%h %s'))
Write-Host ''
$answer = ([string](Read-Host ("Create and push {0} now? [y/N]" -f $tag))).Trim()
if ($answer -ne 'y' -and $answer -ne 'Y') {
	Write-Host 'Aborted. To do it by hand:'
	Write-Host ("      git tag -s {0} -m ""Release {1}""" -f $tag, $Version)
	Write-Host ("      git push origin {0}" -f $tag)
	exit 0
}

& git -C $RepoRoot tag -s $tag -m ("Release {0}" -f $Version)
if ($LASTEXITCODE -ne 0) { throw 'the tag was not created' }
& git -C $RepoRoot push origin $tag
if ($LASTEXITCODE -ne 0) { throw ("the tag exists locally but was not pushed -- retry with: git push origin {0}" -f $tag) }

Write-Host ''
Write-Host ("==> {0} is pushed." -f $tag)
Write-Host '==> Next, publish the release from it on GitHub:'
Write-Host ("      {0}/releases/new?tag={1}" -f $ProjectUrl.TrimEnd('/'), $tag)
Write-Host '    release.yml rebuilds from the tag and attaches the archive once it is published.'