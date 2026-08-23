# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Opens the release branch for a new version: writes meta\Version.ps1 and
	commits the bump on a branch of its own.

	The changelog is folded into that same commit afterwards, so a release
	arrives on main as one pull request and one commit. Nothing is pushed and
	nothing is tagged here -- main is protected, and the tag is only worth
	creating once the pull request is merged.

	Refuses anything that is not a version greater than the latest release tag.

	Usage:
		tools\version.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$VersionPath = Join-Path $RepoRoot 'meta\Version.ps1'

# The version the scripts report, read from the single place that defines it.
. $VersionPath

$branchNow = & git -C $RepoRoot rev-parse --abbrev-ref HEAD
if ($branchNow -ne 'main') {
	throw ("the release branch is cut from main -- you are on '{0}'" -f $branchNow)
}
if (@(& git -C $RepoRoot status --porcelain).Count -gt 0) {
	throw 'the working tree is not clean -- commit or stash first'
}

# Sorted by version, not alphabetically: v1.10.0 comes after v1.9.0.
$latestTag = @(& git -C $RepoRoot tag --list 'v*' --sort=-v:refname) | Select-Object -First 1
$latest = if ($latestTag) { $latestTag.Substring(1) } else { '0.0.0' }

Write-Host 'Maintainer target: opens the release branch with the version bump.'
Write-Host 'main is protected, so the bump arrives as a pull request; the tag comes after the merge.'
Write-Host ''
$new = ([string](Read-Host ("New version (in the sources {0}, latest tag v{1}, empty = abort)" -f $Version, $latest))).Trim()
if (-not $new) {
	Write-Host 'Aborted.'
	exit 0
}
if ($new -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw ("not an X.Y.Z version: {0}" -f $new) }
if ([version]$new -le [version]$latest) {
	throw ("version {0} must be greater than the latest tag v{1}" -f $new, $latest)
}

$branch = "ernolf/release/{0}" -f $new
& git -C $RepoRoot show-ref --verify --quiet ("refs/heads/{0}" -f $branch)
if ($LASTEXITCODE -eq 0) {
	throw ("branch {0} already exists -- delete it or pick another version" -f $branch)
}

& git -C $RepoRoot checkout -b $branch
if ($LASTEXITCODE -ne 0) { throw 'could not create the release branch' }

# One line, and it stays one line: the build, the checks, the packaging and the
# update check all dot-source this file and read $Version out of it.
$line = "`$Version = '{0}'" -f $new
[System.IO.File]::WriteAllBytes($VersionPath, [System.Text.UTF8Encoding]::new($false).GetBytes($line + "`r`n"))

& git -C $RepoRoot add -- 'meta/Version.ps1'
& git -C $RepoRoot commit -s -m ("build(release): bump version to {0}" -f $new)
if ($LASTEXITCODE -ne 0) { throw 'the bump commit failed -- meta\Version.ps1 is written, the commit is not' }

Write-Host ''
Write-Host ("==> Bumped to {0} on {1} and committed." -f $new, $branch)
Write-Host '==> Next, draft the changelog section for it:'
Write-Host '      make.cmd changelog'
Write-Host '    Read it through, then fold it into the bump commit and push:'
Write-Host '      git add CHANGELOG.md'
Write-Host '      git commit --amend --no-edit'
Write-Host ("      git push -u origin {0}" -f $branch)
Write-Host '    Open a pull request and merge it. Then, back on main:'
Write-Host '      git pull'
Write-Host '      make.cmd tag'