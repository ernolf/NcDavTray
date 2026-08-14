# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	Maintenance of the language packs in i18n\.

	Actions:
		normalize   rewrite every pack in canonical form: keys sorted, one tab
		            of indent, no other change to the values
		todo        write build\i18n-todo\<pack>.<lang>.json, holding the keys a
		            translation is missing and the English text as their value
		merge       read translated files from a directory and write their values
		            into the packs, leaving everything else alone

	A key that is missing from a translation is not an error: Initialize-I18n
	merges the embedded English over it, so the string simply shows in English.
	Its absence is what marks it as untranslated, which is why todo never fills a
	gap with English text -- that would hide it.

	Usage:
		tools\i18n.ps1 -Action normalize
		tools\i18n.ps1 -Action todo
		tools\i18n.ps1 -Action merge -From <directory>
#>
[CmdletBinding()]
param(
	[ValidateSet('normalize', 'todo', 'merge')][string]$Action = 'todo',
	[string]$From
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$I18nDir = Join-Path $RepoRoot 'i18n'
$TodoDir = Join-Path $RepoRoot 'build\i18n-todo'

# == JSON, written by hand ==
# ConvertTo-Json is no use here: PowerShell 5.1 escapes every non-ASCII character
# to \uXXXX, indents with four spaces and does not promise to keep the order of
# the keys. All three would rewrite every pack on every run, and six of the seven
# languages are full of accented characters.
function ConvertTo-JsonString([string]$Value) {
	$sb = New-Object System.Text.StringBuilder
	foreach ($ch in $Value.ToCharArray()) {
		switch ($ch) {
			'"' { [void]$sb.Append('\"'); continue }
			'\' { [void]$sb.Append('\\'); continue }
			"`b" { [void]$sb.Append('\b'); continue }
			"`f" { [void]$sb.Append('\f'); continue }
			"`n" { [void]$sb.Append('\n'); continue }
			"`r" { [void]$sb.Append('\r'); continue }
			"`t" { [void]$sb.Append('\t'); continue }
			default {
				# Everything printable stays as it is, so the file keeps its accents
				# and its non-breaking spaces instead of collecting escape sequences.
				if ([int]$ch -lt 0x20) { [void]$sb.AppendFormat('\u{0:x4}', [int]$ch) } else { [void]$sb.Append($ch) }
			}
		}
	}
	return $sb.ToString()
}

function Read-Pack([string]$FilePath) {
	# ConvertFrom-Json keeps the order the file has, which merge relies on.
	$pack = [ordered]@{}
	$json = [System.IO.File]::ReadAllText($FilePath, [System.Text.UTF8Encoding]::new($false))
	foreach ($p in ($json | ConvertFrom-Json).psobject.Properties) { $pack[$p.Name] = [string]$p.Value }
	return $pack
}

function Write-Pack([string]$FilePath, $Pack) {
	# Ordinal, not culture aware: the same repository has to sort the same way on
	# every machine.
	$keys = [string[]]@($Pack.Keys)
	[Array]::Sort($keys, [StringComparer]::Ordinal)
	$lines = New-Object System.Collections.Generic.List[string]
	$lines.Add('{')
	for ($i = 0; $i -lt $keys.Count; $i++) {
		$comma = if ($i -lt $keys.Count - 1) { ',' } else { '' }
		$lines.Add(("`t`"{0}`": `"{1}`"{2}" -f (ConvertTo-JsonString $keys[$i]), (ConvertTo-JsonString $Pack[$keys[$i]]), $comma))
	}
	$lines.Add('}')
	$text = ($lines -join "`r`n") + "`r`n"
	[System.IO.File]::WriteAllBytes($FilePath, [System.Text.UTF8Encoding]::new($false).GetBytes($text))
}

# == Which packs and which languages exist ==
# A pack is named <prefix>i18n.<lang>.json; the English one is the reference,
# every other language is compared against it.
function Get-PackPrefixes {
	return @(Get-ChildItem -LiteralPath $I18nDir -Filter *i18n.en.json | ForEach-Object { $_.Name -replace 'i18n\.en\.json$', '' } | Sort-Object)
}

function Get-Languages {
	$langs = @{}
	foreach ($f in Get-ChildItem -LiteralPath $I18nDir -Filter *i18n.*.json) {
		if ($f.Name -match 'i18n\.([a-z]{2})\.json$' -and $Matches[1] -ne 'en') { $langs[$Matches[1]] = $true }
	}
	return @($langs.Keys | Sort-Object)
}

function Get-PackPath([string]$Prefix, [string]$Lang) {
	return (Join-Path $I18nDir ("{0}i18n.{1}.json" -f $Prefix, $Lang))
}

# == Actions ==

function Invoke-Normalize {
	foreach ($f in (Get-ChildItem -LiteralPath $I18nDir -Filter *.json | Sort-Object Name)) {
		$pack = Read-Pack $f.FullName
		Write-Pack $f.FullName $pack
		Write-Host ("normalized {0}  {1} keys" -f $f.Name, $pack.Count)
	}
}

function Invoke-Todo {
	if (Test-Path -LiteralPath $TodoDir) { Remove-Item -LiteralPath $TodoDir -Recurse -Force }
	[void](New-Item -ItemType Directory -Path $TodoDir -Force)
	$written = 0
	foreach ($prefix in (Get-PackPrefixes)) {
		$en = Read-Pack (Get-PackPath $prefix 'en')
		foreach ($lang in (Get-Languages)) {
			$target = Get-PackPath $prefix $lang
			$have = if (Test-Path -LiteralPath $target) { Read-Pack $target } else { [ordered]@{} }
			$todo = [ordered]@{}
			foreach ($k in $en.Keys) { if (-not $have.Contains($k)) { $todo[$k] = $en[$k] } }
			if ($todo.Count -eq 0) { continue }
			$out = Join-Path $TodoDir (Split-Path -Leaf $target)
			Write-Pack $out $todo
			Write-Host ("todo     {0}  {1} of {2} keys untranslated" -f (Split-Path -Leaf $out), $todo.Count, $en.Count)
			$written++
		}
	}
	if ($written -eq 0) { Write-Host 'todo     nothing untranslated' } else { Write-Host ("ready    {0}" -f $TodoDir) }
}

function Invoke-Merge {
	if (-not $From) { throw 'merge needs -From <directory> holding the translated files' }
	if (-not (Test-Path -LiteralPath $From -PathType Container)) { throw ("no such directory: {0}" -f $From) }
	$failed = $false
	foreach ($f in (Get-ChildItem -LiteralPath $From -Filter *i18n.*.json | Sort-Object Name)) {
		$target = Join-Path $I18nDir $f.Name
		if ($f.Name -notmatch '^(?<prefix>.*)i18n\.(?<lang>[a-z]{2})\.json$') {
			Write-Host ("skipped  {0}  not a language pack name" -f $f.Name); continue
		}
		if ($Matches['lang'] -eq 'en') {
			Write-Host ("skipped  {0}  the English pack is the reference, edit it directly" -f $f.Name); continue
		}
		$enPath = Get-PackPath $Matches['prefix'] 'en'
		if (-not (Test-Path -LiteralPath $enPath)) {
			Write-Host ("skipped  {0}  no English pack for that prefix" -f $f.Name); continue
		}
		$en = Read-Pack $enPath
		$incoming = Read-Pack $f.FullName
		# A key the English pack does not have is a typo, not a translation: writing
		# it would leave a dead entry that nothing ever reads.
		$unknown = @($incoming.Keys | Where-Object { -not $en.Contains($_) })
		if ($unknown.Count -gt 0) {
			$failed = $true
			Write-Host ("FAIL     {0}  unknown keys: {1}" -f $f.Name, ($unknown -join ', '))
			continue
		}
		$pack = if (Test-Path -LiteralPath $target) { Read-Pack $target } else { [ordered]@{} }
		$added = 0
		$changed = 0
		foreach ($k in $incoming.Keys) {
			if (-not $pack.Contains($k)) { $added++ } elseif ($pack[$k] -cne $incoming[$k]) { $changed++ } else { continue }
			$pack[$k] = $incoming[$k]
		}
		Write-Pack $target $pack
		Write-Host ("merged   {0}  {1} added, {2} changed, {3} keys total" -f $f.Name, $added, $changed, $pack.Count)
	}
	if ($failed) { exit 1 }
}

switch ($Action) {
	'normalize' { Invoke-Normalize }
	'todo' { Invoke-Todo }
	'merge' { Invoke-Merge }
}
