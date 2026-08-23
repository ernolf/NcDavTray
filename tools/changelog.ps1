# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Writes the section for the version in meta\Version.ps1 into CHANGELOG.md,
	generated with git-cliff from the conventional commits since the last tag.

	The section is inserted above the previous one and followed by its link
	reference; header, preamble and every hand-written or hand-extended section
	are left as they are.

	What comes out of here is a draft. It is the commits, and the commits are
	written for the people working on the program, not for the people running it:
	they name modules, and they carry every fix made along the way -- including
	the ones to code that did not exist in the last release, which fix nothing
	anybody ever had. Those belong out. Read the section through, throw out what
	the reader of a release cannot have noticed, and say the rest in their words.

	Refuses to write a section that is already there, and says so rather than
	inventing one when there is nothing user-visible to report.

	Needs git-cliff on PATH: winget install orhun.git-cliff

	Usage:
		tools\changelog.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ChangelogPath = Join-Path $RepoRoot 'CHANGELOG.md'
$ConfigPath = Join-Path $RepoRoot 'cliff.toml'

# The version the section is named after is the one the scripts report, read
# from the single place that defines it.
. (Join-Path $RepoRoot 'meta\Version.ps1')

if (-not (Test-Path -LiteralPath $ChangelogPath)) {
	throw ("no {0} -- create it once with a Keep a Changelog header, then run this again" -f $ChangelogPath)
}
if (-not (Get-Command git-cliff -ErrorAction SilentlyContinue)) {
	throw 'git-cliff is not on PATH -- install it with: winget install orhun.git-cliff'
}

$existing = [System.IO.File]::ReadAllText($ChangelogPath, [System.Text.UTF8Encoding]::new($false))
# Whatever line ending the file already uses stays its line ending: a section
# appended in the other one turns the whole file into a diff.
$eol = if ($existing -match "`r`n") { "`r`n" } else { "`n" }
$lines = $existing -split "`r?`n"

if ($existing -match ("(?m)^## \[{0}\]" -f [regex]::Escape($Version))) {
	Write-Host ("CHANGELOG.md already has a [{0}] section -- nothing to do." -f $Version)
	exit 0
}

Write-Host ("==> Generating the [{0}] section from the commits since the last tag..." -f $Version)
# git-cliff writes UTF-8, but Windows PowerShell decodes what a native command
# prints with [Console]::OutputEncoding, which is the console's OEM code page
# unless something set it otherwise. An em dash would arrive as the three
# characters its UTF-8 bytes happen to mean in that code page, and be written
# back into the file as those three -- the section is generated once and read
# for years, so it cannot depend on which console it was generated in.
$previousOutputEncoding = [Console]::OutputEncoding
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
	$generated = & git-cliff --config $ConfigPath --unreleased --tag ("v{0}" -f $Version) 2>$null
	if ($LASTEXITCODE -ne 0) { throw 'git-cliff failed' }
} finally {
	[Console]::OutputEncoding = $previousOutputEncoding
}
# Trimmed because git-cliff frames its output with blank lines even when the
# configured header and footer are empty, and those land in the middle of the file.
$section = (@($generated) -join "`n").Trim()

# A release can be real work and still have nothing in it that a user of the
# program can notice -- a build system, a test, a rewritten page. Saying so is
# the honest answer; a section made of the commits that were deliberately left
# out would be worse than none.
if ($section -notmatch '(?m)^### ') {
	Write-Host 'No user-visible changes since the last tag (only commit types that are left out).'
	Write-Host ("Write a [{0}] section by hand if the release warrants one anyway." -f $Version)
	exit 0
}

# The link reference the section title resolves to. The remote is where the
# repository actually lives, which a URL written down here would only claim.
$origin = & git -C $RepoRoot remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0 -and $origin -match 'github\.com[:/](.+?)(?:\.git)?/?\s*$') {
	$section += "`n`n[{0}]: https://github.com/{1}/releases/tag/v{0}" -f $Version, $Matches[1]
}

# Above the newest section there is, or at the end when this is the first one.
$at = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
	if ($lines[$i] -match '^## \[') { $at = $i; break }
}
$new = [string[]](@($section -split "`n") + @(''))
$merged = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $lines.Count; $i++) {
	if ($i -eq $at) { $merged.AddRange($new) }
	$merged.Add([string]$lines[$i])
}
if ($at -lt 0) { $merged.AddRange($new) }

$out = ($merged -join $eol)
[System.IO.File]::WriteAllBytes($ChangelogPath, [System.Text.UTF8Encoding]::new($false).GetBytes($out))

Write-Host ("==> Inserted the [{0}] section into CHANGELOG.md." -f $Version)
Write-Host '==> Read it through and rewrite what reads like a commit subject, then commit it:'

# While the bump commit tools\version.ps1 wrote is still unpushed, the changelog
# belongs in it -- one commit per release, and one place to review it.
$lastSubject = & git -C $RepoRoot log -1 --pretty=%s
& git -C $RepoRoot rev-parse -q --verify '@{u}' > $null
$pushed = ($LASTEXITCODE -eq 0) -and ((& git -C $RepoRoot rev-parse HEAD) -eq (& git -C $RepoRoot rev-parse '@{u}'))
Write-Host '      git add CHANGELOG.md'
if (-not $pushed -and $lastSubject -eq ("build(release): bump version to {0}" -f $Version)) {
	Write-Host '      git commit --amend --no-edit'
	Write-Host ("      git push -u origin {0}" -f (& git -C $RepoRoot rev-parse --abbrev-ref HEAD))
	Write-Host '    which keeps the release at one commit. Then open a pull request and merge it.'
} else {
	Write-Host ("      git commit -s -m ""build(release): update changelog for {0}""" -f $Version)
}
