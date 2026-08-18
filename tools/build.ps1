# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	NcDavTray build script.

	Assembles the deliverable scripts from the templates in templates\ and puts
	them, together with everything else that ships, into build\<product folder>.
	Nothing in build\ is under version control -- the repository holds sources,
	the build holds results.

	A template is an ordinary PowerShell script in which single lines have been
	replaced by placeholders. At build time each placeholder line is replaced by
	the content of the file it points to, so the same module can be shared by
	more than one target without duplicating it in the codebase.

	Placeholder syntax - a whole line, starting at column 0:

		#__inc:<path>__     insert the file's text verbatim (one trailing
		                    newline in the source file is dropped)
		#__b64:<path>__     insert the file's bytes as a single base64 line
		#__i18n:<path>__    insert the language pack, reduced to the keys this
		                    script refers to

	<path> is relative to the repository root.

	#__i18n: is resolved in a second pass, after every #__inc: has been put in,
	because it needs the assembled script to see which keys it uses. Both
	deliverables read one shared pack per language, but neither has to carry the
	other's strings in its compiled-in fallback.

	A note is a comment marked with __note__ that belongs to the source and not
	to the deliverable (see Remove-Notes for how one is written). The build
	drops notes once the script is assembled, template and modules alike: last
	of all, so a note may stand anywhere, and only notes -- every other comment
	ships.

	Usage:
		tools\build.ps1            assemble build\NcDavTray
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot

# == Layout ==
. (Join-Path $RepoRoot 'meta\AppName.ps1')
$BuildDir = Join-Path $RepoRoot 'build'
# The folder the user ends up with after unpacking, so it is also the folder
# inside the release archive.
$ProductDir = Join-Path $BuildDir $AppName

# == Targets ==
$Targets = @(
	@{ Template = 'templates\NDT.ps1.in'; Output = 'NDT.ps1' }
)

# Files that ship next to the scripts, copied rather than assembled.
$Extras = @(
	@{ From = 'installer\Installer.cmd'; To = 'Installer.cmd' }
)

# the line terminator is matched by lookahead only, so it survives the replacement
$PlaceholderRx = [regex]'(?m)^#__(?<kind>inc|b64):(?<path>[^\r\n]+?)__[ \t]*(?=\r?$)'
$I18nPlaceholderRx = [regex]'(?m)^#__i18n:(?<path>[^\r\n]+?)__[ \t]*(?=\r?$)'
# one "key": "value" per line is the canonical pack format, which tools\i18n.ps1
# produces and `make check` enforces
$PackLineRx = [regex]'(?m)^\s*"((?:[^"\\]|\\.)*)"\s*:'
# The compiled-in fallback lives inside the script, and PowerShell 5.1 reads a
# script without a BOM as CP1252 -- anything above U+007F would reach the user as
# mojibake. The pack itself may use real typography; this table is how it becomes
# ASCII on the way in, so the fallback is plain and the shipped pack stays pretty.
# It is JSON and read as UTF-8 on purpose: a .ps1 or .psd1 holding these same
# characters would be misread exactly the way this table exists to prevent.
$AsciiFoldPath = Join-Path $PSScriptRoot 'ascii-fold.json'

function Resolve-RepoPath([string]$Relative) {
	$p = Join-Path $RepoRoot $Relative
	if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
		throw ("referenced file not found: {0}" -f $Relative)
	}
	return $p
}

function Read-TextNoBom([string]$Path) {
	return [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
}

function Expand-Template([string]$TemplatePath) {
	# Everything is assembled with plain newlines and converted once at the end,
	# so that template and module never have to agree on a convention.
	$text = (Read-TextNoBom $TemplatePath) -replace "`r`n", "`n"
	$evaluator = {
		param($m)
		$rel = $m.Groups['path'].Value
		$src = Resolve-RepoPath $rel
		switch ($m.Groups['kind'].Value) {
			'b64' {
				return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($src))
			}
			'inc' {
				$body = (Read-TextNoBom $src) -replace "`r`n", "`n"
				return ($body -replace "`n+$", '')
			}
		}
	}
	return $PlaceholderRx.Replace($text, $evaluator)
}

# Every string literal the script contains. Keys reach T and its relatives either
# as a literal argument or through a variable that was assigned one a few lines
# earlier, so taking all literals and not just the arguments of key-taking
# commands is what makes the filter below safe. A key assembled from fragments at
# runtime would escape it -- there is none, and `make check` would not catch one,
# so keys stay whole strings.
function Get-StringLiterals([string]$Text) {
	$errors = $null
	$ast = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$null, [ref]$errors)
	if ($errors -and $errors.Count -gt 0) {
		throw ("cannot read the assembled script: {0}" -f $errors[0].Message)
	}
	$found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
	$set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
	foreach ($n in $found) { [void]$set.Add($n.Value) }
	return $set
}

# The pack is filtered line by line rather than parsed and written back, so every
# value keeps its escaping byte for byte and only the trailing commas move.
function Select-PackKeys([string]$PackPath, $Keys) {
	$lines = (Read-TextNoBom $PackPath) -replace "`r`n", "`n" -split "`n"
	$kept = @()
	foreach ($line in $lines) {
		$m = $PackLineRx.Match($line)
		if (-not $m.Success) { continue }
		if ($Keys.Contains($m.Groups[1].Value)) { $kept += ($line -replace ',\s*$', '') }
	}
	$body = @()
	for ($i = 0; $i -lt $kept.Count; $i++) {
		$body += $(if ($i -lt $kept.Count - 1) { $kept[$i] + ',' } else { $kept[$i] })
	}
	return (@('{') + $body + @('}')) -join "`n"
}

# A character the table does not cover would end up in the script as a byte the
# user's PowerShell reads as something else, so the build stops instead of
# shipping it. Adding a row to ascii-fold.json is the fix; `make check` says the
# same thing earlier, on the pack rather than on the build.
function Convert-PackToAscii([string]$Text, [string]$PackPath) {
	$json = [System.IO.File]::ReadAllText($AsciiFoldPath, [System.Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
	foreach ($rule in $json.psobject.Properties) { $Text = $Text.Replace($rule.Name, [string]$rule.Value) }
	$bad = @()
	foreach ($line in ($Text -split "`n")) {
		if ($line -notmatch '[^\x00-\x7F]') { continue }
		$key = $PackLineRx.Match($line)
		$chars = @([regex]::Matches($line, '[^\x00-\x7F]') | ForEach-Object { 'U+{0:X4}' -f [int][char]$_.Value } | Sort-Object -Unique)
		$bad += ("{0}  {1}" -f $(if ($key.Success) { $key.Groups[1].Value } else { '<unnamed line>' }), ($chars -join ' '))
	}
	if ($bad.Count -gt 0) {
		throw ("{0} uses characters with no rule in {1}:{2}  {3}" -f (Split-Path -Leaf $PackPath), (Split-Path -Leaf $AsciiFoldPath), [Environment]::NewLine, ($bad -join ([Environment]::NewLine + '  ')))
	}
	return $Text
}

function Expand-I18n([string]$Text) {
	$literals = Get-StringLiterals $Text
	$evaluator = {
		param($m)
		$src = Resolve-RepoPath $m.Groups['path'].Value
		$reduced = Convert-PackToAscii (Select-PackKeys $src $literals) $src
		Write-Host ("         i18n  {0} of {1} keys" -f (@($reduced -split "`n").Count - 2), (@($PackLineRx.Matches((Read-TextNoBom $src))).Count))
		return $reduced
	}
	return $I18nPlaceholderRx.Replace($Text, $evaluator)
}

# A note is written as "#__note__ <text>", which runs to the end of the line, or
# opened with "<#__note__ <text>" and closed the way any block comment is closed,
# which runs over as many lines as it takes. Both are ordinary comments, so an
# editor, the parser and `make check` see them for what they are, and there is no
# marker of its own that could be left unclosed.
#
# Notes are taken out by the parser rather than by a pattern over the text: a
# '#' inside a string or a regex is not a comment, and no expression can tell
# the two apart. Whatever is left of the line goes with the note, and a note
# that had a line to itself takes the line with it, so nothing is left behind
# where one stood. The script is assembled at this point, which is why a note in
# a module and a note in the template are the same thing here.
function Remove-Notes([string]$Text) {
	$tokens = $null
	$errors = $null
	[void][System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
	if ($errors -and $errors.Count -gt 0) {
		throw ("cannot read the assembled script: {0} (line {1})" -f $errors[0].Message, $errors[0].Extent.StartLineNumber)
	}
	$notes = @($tokens | Where-Object { $_.Kind -eq 'Comment' -and $_.Text -match '^<?#__note__' })
	# from the back, so every offset still points where it did when it was read
	for ($i = $notes.Count - 1; $i -ge 0; $i--) {
		$from = $notes[$i].Extent.StartOffset
		$to = $notes[$i].Extent.EndOffset
		while ($from -gt 0 -and ($Text[$from - 1] -eq ' ' -or $Text[$from - 1] -eq "`t")) { $from-- }
		$rest = $to
		while ($rest -lt $Text.Length -and ($Text[$rest] -eq ' ' -or $Text[$rest] -eq "`t")) { $rest++ }
		if (($from -eq 0 -or $Text[$from - 1] -eq "`n") -and ($rest -ge $Text.Length -or $Text[$rest] -eq "`n")) {
			$to = [Math]::Min($rest + 1, $Text.Length)
		}
		$Text = $Text.Remove($from, $to - $from)
	}
	Write-Host ("         notes  {0} removed" -f $notes.Count)
	return $Text
}

# The deliverables are Windows scripts and .gitattributes states as much for
# every .ps1 in the repository. Until now git enforced that on checkout, but the
# build output has left the repository, so the build has to state it itself --
# otherwise the line endings of a release would depend on the git configuration
# of whoever ran the build.
function ConvertTo-Crlf([string]$Text) { return ($Text -replace "`n", "`r`n") }

# A build starts from nothing: a file that stops being produced has to disappear
# from the result as well, and a stale one is worse than a missing one.
if (Test-Path -LiteralPath $ProductDir) { Remove-Item -LiteralPath $ProductDir -Recurse -Force }
[void](New-Item -ItemType Directory -Path $ProductDir -Force)

foreach ($t in $Targets) {
	$built = ConvertTo-Crlf (Remove-Notes (Expand-I18n (Expand-Template (Join-Path $RepoRoot $t.Template))))
	$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($built)
	[System.IO.File]::WriteAllBytes((Join-Path $ProductDir $t.Output), $bytes)
	Write-Host ("built    {0}  {1} bytes" -f $t.Output, $bytes.Length)
}

foreach ($e in $Extras) {
	Copy-Item -LiteralPath (Resolve-RepoPath $e.From) -Destination (Join-Path $ProductDir $e.To) -Force
	Write-Host ("copied   {0}" -f $e.To)
}

# English ships as a file like every other language. The copy compiled into the
# script is the same pack folded to ASCII, and Initialize-I18n merges the file
# over it key by key: with the file present the user reads the typography as
# written, without it the fallback still says the same thing in plain characters.
$i18nDir = Join-Path $ProductDir 'i18n'
[void](New-Item -ItemType Directory -Path $i18nDir -Force)
$packs = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'i18n') -Filter *.json)
foreach ($p in $packs) { Copy-Item -LiteralPath $p.FullName -Destination $i18nDir -Force }
Write-Host ("copied   i18n\  {0} language packs" -f $packs.Count)

Write-Host ("ready    {0}" -f $ProductDir)
