# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Every target this repository has. CI runs these and nothing else, so that
	what a release is built from is what a contributor can run at home.

	The repository holds sources. The deliverables are assembled from them into
	build\, which is not under version control -- so a build result is never
	committed and can never drift from the sources it came from.

	Targets:
		build           assemble build\NcDavTray from templates\, modules\,
		                assets\, i18n\ and installer\
		check           build, then run the static checks over the result
		dist            build, then pack the release archive into build\
		clean           delete build\
		changelog       write the section for the current version into
		                CHANGELOG.md, generated from the commits since the
		                last tag -- a draft to read through, not a result
		i18n            write build\i18n-todo\ for the translators: per language
		                the keys it is missing and the English text as their value
		i18n-merge      read translated files from -From and write their values
		                into i18n\
		i18n-normalize  rewrite i18n\ in canonical form, values unchanged
		help            list the targets

	`check` is the default. Use make.cmd rather than calling this directly.
#>
[CmdletBinding()]
param(
	[ValidateSet('build', 'check', 'dist', 'clean', 'changelog', 'i18n', 'i18n-merge', 'i18n-normalize', 'help')][string]$Target = 'check',
	[string]$From
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Each step runs in its own powershell.exe rather than in this session: the
# deliverables are Windows PowerShell 5.1 scripts and the checks parse them with
# the engine they will run on, whatever host was used to start make.ps1. A child
# process also reports its exit code reliably, which a called script that ends in
# exit does not.
function Invoke-Step {
	param([Parameter(Mandatory)][string]$Script, [string[]]$Arguments = @())
	& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot $Script) @Arguments
	if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

switch ($Target) {
	'build' { Invoke-Step 'tools\build.ps1' }
	'check' { Invoke-Step 'tools\build.ps1'; Invoke-Step 'tools\checks.ps1' }
	'dist' { Invoke-Step 'tools\build.ps1'; Invoke-Step 'tools\dist.ps1' }
	'clean' {
		$buildDir = Join-Path $PSScriptRoot 'build'
		if (Test-Path -LiteralPath $buildDir) { Remove-Item -LiteralPath $buildDir -Recurse -Force }
		Write-Host ("cleaned  {0}" -f $buildDir)
	}
	'changelog' { Invoke-Step 'tools\changelog.ps1' }
	'i18n' { Invoke-Step 'tools\i18n.ps1' @('-Action', 'todo') }
	'i18n-merge' {
		if (-not $From) { throw 'i18n-merge needs -From <directory> holding the translated files' }
		Invoke-Step 'tools\i18n.ps1' @('-Action', 'merge', '-From', $From)
	}
	'i18n-normalize' { Invoke-Step 'tools\i18n.ps1' @('-Action', 'normalize') }
	'help' {
		# The comment block above is the one description of the targets there is;
		# help reads it back out rather than keeping a copy that goes stale.
		$doc = [System.IO.File]::ReadAllText($PSCommandPath)
		if ($doc -match '(?ms)^\tTargets:\r?\n(.+?)\r?\n\s*\r?\n') { Write-Host ($Matches[1] -replace '(?m)^\t\t', '  ') }
	}
}
