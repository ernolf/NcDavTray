# SPDX-FileCopyrightText: 2026 [ernolf] Raphael Gradenwitz <raphael.gradenwitz@googlemail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

<#
	NcDavTray static checks.

	Runs over the built scripts in build/ and reports what a syntax check alone
	cannot see. The deliverables are single files without modules or tests, so
	these checks stand in for what an import would otherwise reveal:

		syntax      the file parses
		commands    every command called is either defined in the file itself
		            or available from PowerShell
		variables   every variable read is assigned somewhere in the file
		            (the scripts run without Set-StrictMode, so an undefined
		            variable is silently $null instead of an error)
		i18n        every literal key handed to T() exists in the language data
		            embedded in that same script
		members     no method called on a window is one of the form's own: what is
		            protected on Form or Control cannot be reached from a script,
		            and the call only fails when that window opens

	And over the sources in modules\ and templates\:

		style       the one line the code is written in: no line continued with
		            a backtick, nothing padded to line up, tabs for indentation,
		            no brace on a line of its own, no blank line at the end.
		            Reported against the source, because that is where the line
		            can be changed

	And over the bootstrap in build\:

		actions     every -Action Installer.cmd passes is one the script it calls
		            accepts (PowerShell refuses an unknown one at the parameter,
		            before a line of the script runs)

	And over the language packs in i18n\:

		json            the file parses
		keys            a translation has every key the English pack has, and no
		                key it does not (a warning: a missing key shows in English)
		placeholders    a translated string carries the same {placeholders} as its
		                English original

	Usage:
		tools\checks.ps1                 check every built script
		tools\checks.ps1 -Path a.ps1     check the given files instead

	Run it with Windows PowerShell 5.1: that is what the deliverables target.
#>
[CmdletBinding()]
param(
	[string[]]$Path = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms

$RepoRoot = Split-Path -Parent $PSScriptRoot

if ($Path.Count -eq 0) {
	$productDir = Join-Path $RepoRoot 'build\NcDavTray'
	if (-not (Test-Path -LiteralPath $productDir -PathType Container)) {
		throw ("nothing to check: {0} does not exist -- build first" -f $productDir)
	}
	$Path = @(Get-ChildItem -LiteralPath $productDir -Filter *.ps1 | ForEach-Object { $_.FullName })
}

# Names PowerShell provides on its own, so nothing assigns them in the scripts.
$AutomaticVariables = @(
	'_', 'args', 'ConfirmPreference', 'ErrorActionPreference', 'error', 'ExecutionContext',
	'false', 'foreach', 'Host', 'HOME', 'input', 'LASTEXITCODE', 'Matches', 'MyInvocation',
	'null', 'OutputEncoding', 'PID', 'ProgressPreference', 'PSBoundParameters', 'PSCmdlet',
	'PSCommandPath', 'PSCulture', 'PSDefaultParameterValues', 'PSItem', 'PSScriptRoot',
	'PSUICulture', 'PSVersionTable', 'PWD', 'StackTrace', 'switch', 'this', 'true',
	'VerbosePreference', 'WarningPreference'
)

function Get-BareName([string]$UserPath) {
	return ($UserPath -replace '^(script|global|local|private|using|env):', '')
}

# --- checks, one function each, all returning the problems they found ---

function Test-Commands($Ast) {
	$defined = @{}
	foreach ($f in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
		$defined[($f.Name -replace '^global:', '')] = $true
	}
	$problems = @()
	$seen = @{}
	foreach ($c in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
		$name = $c.GetCommandName()
		if (-not $name -or $seen.ContainsKey($name)) { continue }
		$seen[$name] = $true
		if ($defined.ContainsKey($name)) { continue }
		if (Get-Command -Name $name -ErrorAction SilentlyContinue) { continue }
		$problems += ("unresolved command '{0}' (line {1})" -f $name, $c.Extent.StartLineNumber)
	}
	return , $problems
}

function Test-Variables($Ast) {
	$assigned = @{}
	foreach ($n in $AutomaticVariables) { $assigned[$n] = $true }
	foreach ($a in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
		$left = $a.Left
		if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
		if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
			$assigned[(Get-BareName $left.VariablePath.UserPath)] = $true
		}
	}
	foreach ($p in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)) {
		$assigned[(Get-BareName $p.Name.VariablePath.UserPath)] = $true
	}
	foreach ($f in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)) {
		$assigned[(Get-BareName $f.Variable.VariablePath.UserPath)] = $true
	}
	$problems = @()
	$seen = @{}
	foreach ($v in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
		$userPath = $v.VariablePath.UserPath
		if ($userPath -like 'env:*') { continue }
		$name = Get-BareName $userPath
		if ($assigned.ContainsKey($name) -or $seen.ContainsKey($name)) { continue }
		$seen[$name] = $true
		$problems += ("variable `${0} is read but never assigned (line {1})" -f $name, $v.Extent.StartLineNumber)
	}
	return , $problems
}

# The language data is embedded in the script as a here-string, so the keys are
# checked against what the script itself will use at runtime and not against a
# file it might have been built from.
function Test-I18nKeys($Ast) {
	$json = $null
	foreach ($a in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
		$left = $a.Left
		if (-not ($left -is [System.Management.Automation.Language.VariableExpressionAst])) { continue }
		if ((Get-BareName $left.VariablePath.UserPath) -ne 'I18N_Embedded_En') { continue }
		$right = $a.Right
		if ($right -is [System.Management.Automation.Language.CommandExpressionAst]) { $right = $right.Expression }
		if ($right -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $json = $right.Value }
	}
	if ($null -eq $json) { return @('no embedded language data found') }
	$keys = @{}
	try {
		foreach ($p in ($json | ConvertFrom-Json).psobject.Properties) { $keys[$p.Name] = $true }
	} catch { return @("embedded language data is not valid JSON: $($_.Exception.Message)") }
	# Every function taking a key does so as its first parameter named $Key: T
	# itself, the message boxes, the Ask helpers. Collecting them by that signature
	# keeps the check right when another one is added.
	$keyCommands = @{}
	foreach ($f in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
		$params = if ($f.Parameters) { $f.Parameters } elseif ($f.Body.ParamBlock) { $f.Body.ParamBlock.Parameters } else { $null }
		if (-not $params -or @($params).Count -eq 0) { continue }
		if ((Get-BareName @($params)[0].Name.VariablePath.UserPath) -eq 'Key') { $keyCommands[($f.Name -replace '^global:', '')] = $true }
	}
	$problems = @()
	$seen = @{}
	foreach ($c in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
		$name = $c.GetCommandName()
		if (-not $name -or -not $keyCommands.ContainsKey($name)) { continue }
		$elements = $c.CommandElements
		if ($elements.Count -lt 2) { continue }
		$arg = $elements[1]
		if ($arg -is [System.Management.Automation.Language.CommandParameterAst]) {
			if ($arg.ParameterName -ne 'Key' -or $elements.Count -lt 3) { continue }
			$arg = $elements[2]
		}
		# Keys built at runtime cannot be checked here, only literal ones
		if (-not ($arg -is [System.Management.Automation.Language.StringConstantExpressionAst])) { continue }
		$key = $arg.Value
		if ($keys.ContainsKey($key) -or $seen.ContainsKey($key)) { continue }
		$seen[$key] = $true
		$problems += ("i18n key '{0}' is used but not defined (line {1})" -f $key, $c.Extent.StartLineNumber)
	}
	return , $problems
}

# Everything a window does from the outside has to be public. OnLoad, WndProc,
# CenterToScreen and the rest are the form's own business: PowerShell does not
# find them, and it says so when the window opens -- on the machine that opened
# it, not here. The names come from the type itself, so nothing has to be kept
# in a list.
function Test-FormMembers($Ast) {
	$open = [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::Public
	$shut = [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic
	$public = @{}; $hidden = @{}
	foreach ($type in @([System.Windows.Forms.Form], [System.Windows.Forms.Control])) {
		foreach ($m in $type.GetMembers($open)) { $public[$m.Name] = $true }
		foreach ($m in $type.GetMethods($shut)) { $hidden[$m.Name] = $true }
	}
	$problems = @()
	$seen = @{}
	foreach ($call in $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
		if ($call.Static) { continue }
		if ($call.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
		$name = $call.Member.Value
		if ($seen.ContainsKey($name) -or $public.ContainsKey($name) -or -not $hidden.ContainsKey($name)) { continue }
		$seen[$name] = $true
		$problems += ("'{0}' is not public on a form (line {1})" -f $name, $call.Extent.StartLineNumber)
	}
	return , $problems
}

# The style is the one the single script of 1.2.2 established: compact, nothing
# wrapped for width, nothing padded to line up. It reads tokens rather than
# lines, and that is the whole point -- a here-string and a block comment are one
# token each, they carry their own escaping and their own layout, and a pattern
# over lines would report every one of them. What a note is marked with does not
# matter here either: a note is a comment like any other, and the build is what
# tells them apart.
function Get-StyleProblems([string]$Path) {
	$name = Split-Path -Leaf $Path
	$text = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false)) -replace "`r`n", "`n"
	$lines = $text -split "`n"
	$tokens = $null
	$errors = $null
	$ast = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors)
	if ($errors -and $errors.Count -gt 0) {
		return @{ Errors = @("{0}:{1}  {2}" -f $name, $errors[0].Extent.StartLineNumber, $errors[0].Message); Hints = @() }
	}
	# every line a token reaches into, which is where the tokenizer earns its keep
	$inside = @{}
	foreach ($t in $tokens) {
		for ($i = $t.Extent.StartLineNumber + 1; $i -le $t.Extent.EndLineNumber; $i++) { $inside[$i] = $true }
	}
	$problems = @()
	$previous = $null
	foreach ($t in $tokens) {
		if ($t.Kind -eq 'LineContinuation') {
			$problems += ("{0}:{1}  line continued with a backtick" -f $name, $t.Extent.StartLineNumber)
			# what follows is the same statement, and its indentation is not padding
			$previous = $null
			continue
		}
		if ($t.Kind -eq 'NewLine' -or $t.Kind -eq 'EndOfInput') { $previous = $null; continue }
		if ($previous -and $previous.Extent.EndLineNumber -eq $t.Extent.StartLineNumber) {
			$gap = $t.Extent.StartColumnNumber - $previous.Extent.EndColumnNumber
			$token = $t.Text -replace "`n.*", '...'
			if ($gap -gt 1) { $problems += ("{0}:{1}  {2} spaces before '{3}'" -f $name, $t.Extent.StartLineNumber, $gap, $token) }
		}
		$previous = $t
	}
	for ($i = 0; $i -lt $lines.Count; $i++) {
		if ($inside.ContainsKey($i + 1)) { continue }
		$line = $lines[$i]
		if (-not $line.Trim()) { continue }
		if ($line -match '^\t* ') { $problems += ("{0}:{1}  indented with spaces" -f $name, ($i + 1)) }
		if ($line.Trim() -eq '{') { $problems += ("{0}:{1}  brace on a line of its own" -f $name, ($i + 1)) }
	}
	if ($text -match "\n[ \t]*\n+$") { $problems += ("{0}  blank line at the end" -f $name) }
	# A param() over several lines is not always avoidable -- a comment between two
	# parameters has nowhere else to go -- so this is said, not enforced.
	$hints = @()
	foreach ($p in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParamBlockAst] }, $true)) {
		$span = $p.Extent.EndLineNumber - $p.Extent.StartLineNumber + 1
		if ($span -gt 1) { $hints += ("{0}:{1}  param() over {2} lines" -f $name, $p.Extent.StartLineNumber, $span) }
	}
	return @{ Errors = $problems; Hints = $hints }
}

# The values a script accepts for -Action, or $null when it does not take one.
function Get-ActionValidateSet($Ast) {
	if (-not $Ast.ParamBlock) { return $null }
	foreach ($p in $Ast.ParamBlock.Parameters) {
		if ((Get-BareName $p.Name.VariablePath.UserPath) -ne 'Action') { continue }
		foreach ($a in $p.Attributes) {
			if ($a -isnot [System.Management.Automation.Language.AttributeAst]) { continue }
			if ($a.TypeName.Name -ne 'ValidateSet') { continue }
			return @($a.PositionalArguments | ForEach-Object { [string]$_.Value })
		}
	}
	return $null
}

# --- run ---

$failed = $false

function Write-Result([string]$Name, [string]$Check, $Problems, [switch]$Warn) {
	$problemList = @($Problems)
	$tag = if ($problemList.Count -eq 0) { 'OK' } elseif ($Warn) { 'WARN' } else { 'FAIL' }
	if ($problemList.Count -gt 0 -and -not $Warn) { $script:failed = $true }
	Write-Host ("{0,-8} {1}  {2}" -f $tag, $Name, $Check)
	foreach ($p in $problemList) { Write-Host ("  {0}" -f $p) }
}

$asts = @{}
foreach ($file in $Path) {
	$full = if ([System.IO.Path]::IsPathRooted($file)) { $file } else { Join-Path $RepoRoot $file }
	$name = Split-Path -Leaf $full
	$tokens = $null
	$errors = $null
	$ast = [System.Management.Automation.Language.Parser]::ParseFile($full, [ref]$tokens, [ref]$errors)
	$syntax = @($errors | ForEach-Object { "{0} (line {1})" -f $_.Message, $_.Extent.StartLineNumber })
	Write-Result $name 'syntax' $syntax
	# Everything below walks the tree, which a broken file does not have
	if ($syntax.Count -gt 0) { continue }
	$asts[$name] = $ast
	Write-Result $name 'commands' (Test-Commands $ast)
	Write-Result $name 'variables' (Test-Variables $ast)
	Write-Result $name 'i18n' (Test-I18nKeys $ast)
	Write-Result $name 'members' (Test-FormMembers $ast)
}

# The only check that does not look at build\: a line number is worth something
# where the line can be edited, and in the build every one of them has moved.
$sources = @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'modules') -Filter *.ps1)
$sources += @(Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'templates') -Filter *.ps1.in)
$styleProblems = @()
$styleHints = @()
foreach ($src in ($sources | Sort-Object Name)) {
	$found = Get-StyleProblems $src.FullName
	$styleProblems += $found.Errors
	$styleHints += $found.Hints
}
$styleName = "{0} sources" -f $sources.Count
Write-Result $styleName 'style' $styleProblems
Write-Result $styleName 'style, worth a look' $styleHints -Warn

# The bootstrap and the script it drives are two files that have to agree, and
# nothing at runtime can tell them apart: an -Action the ValidateSet does not know
# is refused while the parameters are still being bound, so the script never gets
# far enough to say anything about it.
$bootstrap = Join-Path $RepoRoot 'build\NcDavTray\Installer.cmd'
if (Test-Path -LiteralPath $bootstrap) {
	$problems = @()
	$text = [System.IO.File]::ReadAllText($bootstrap)
	$called = 'NDT.ps1'
	$m = [regex]::Match($text, '(?im)^\s*set\s+"_PS1=(?<f>[^"]+)"')
	if ($m.Success) { $called = $m.Groups['f'].Value }
	if (-not $asts.ContainsKey($called)) { $problems += ('calls {0}, which is not among the built scripts' -f $called) }
	else {
		$allowed = Get-ActionValidateSet $asts[$called]
		if ($null -eq $allowed) { $problems += ('{0} takes no -Action' -f $called) }
		else {
			foreach ($hit in [regex]::Matches($text, '-Action\s+(?<a>[A-Za-z]\w*)')) {
				$value = $hit.Groups['a'].Value
				if ($allowed -notcontains $value) { $problems += ('-Action {0} is not one of: {1}' -f $value, (($allowed | Where-Object { $_ }) -join ', ')) }
			}
		}
	}
	Write-Result (Split-Path -Leaf $bootstrap) 'actions' $problems
}

# The translations are not embedded, they are read at runtime -- a broken file
# would only show up on the machine that has that language.
$packs = @{}
foreach ($lang in (Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'i18n') -Filter *.json | Sort-Object Name)) {
	$problems = @()
	try { $packs[$lang.Name] = [System.IO.File]::ReadAllText($lang.FullName, [System.Text.UTF8Encoding]::new($false)) | ConvertFrom-Json }
	catch { $problems = @($_.Exception.Message) }
	Write-Result $lang.Name 'json' $problems
}

function Get-Placeholders([string]$Text) {
	return @([regex]::Matches($Text, '\{[a-zA-Z0-9_]+\}') | ForEach-Object { $_.Value } | Sort-Object)
}

# Each translation is held against the English pack of the same name. A key it does
# not have is a gap, not a fault: Initialize-I18n merges the embedded English over
# it and the string shows in English, so this warns rather than fails. A key the
# English pack no longer has is dead weight, and warns too. A placeholder that
# differs does break the string it stands in, and fails.
foreach ($name in ($packs.Keys | Sort-Object)) {
	if ($name -notmatch '^(?<prefix>.*)i18n\.(?<lang>[a-z]{2})\.json$') { continue }
	if ($Matches['lang'] -eq 'en') { continue }
	$enName = "{0}i18n.en.json" -f $Matches['prefix']
	if (-not $packs.ContainsKey($enName)) { continue }
	$en = $packs[$enName]
	$tr = $packs[$name]
	$enKeys = @($en.psobject.Properties.Name)
	$trKeys = @($tr.psobject.Properties.Name)
	$missing = @($enKeys | Where-Object { $trKeys -notcontains $_ })
	$orphan = @($trKeys | Where-Object { $enKeys -notcontains $_ })
	$gaps = @()
	if ($missing.Count -gt 0) { $gaps += ("{0} of {1} keys untranslated: {2}" -f $missing.Count, $enKeys.Count, ($missing -join ', ')) }
	if ($orphan.Count -gt 0) { $gaps += ("{0} keys the English pack does not have: {1}" -f $orphan.Count, ($orphan -join ', ')) }
	Write-Result $name 'keys' $gaps -Warn
	$broken = @()
	foreach ($k in $trKeys) {
		if ($enKeys -notcontains $k) { continue }
		$want = Get-Placeholders $en.$k
		$got = Get-Placeholders $tr.$k
		if (($want -join ',') -ne ($got -join ',')) {
			$broken += ("'{0}' has [{1}] instead of [{2}]" -f $k, ($got -join ' '), ($want -join ' '))
		}
	}
	Write-Result $name 'placeholders' $broken
}

# English is also the fallback compiled into each script, where PowerShell 5.1
# reads it as CP1252 for want of a BOM -- so the build folds it to ASCII first.
# Every character it has to fold needs a rule; one without would stop the build,
# and this names the key it sits in rather than leaving that to the build step.
$fold = [System.IO.File]::ReadAllText((Join-Path $PSScriptRoot 'ascii-fold.json'), [System.Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
$covered = @($fold.psobject.Properties.Name)
foreach ($name in ($packs.Keys | Sort-Object)) {
	if ($name -notmatch 'i18n\.en\.json$') { continue }
	$problems = @()
	foreach ($p in $packs[$name].psobject.Properties) {
		# A folded key would no longer match the one the translations use
		if ($p.Name -match '[^\x00-\x7F]') { $problems += ("key '{0}' is not ASCII" -f $p.Name); continue }
		$loose = @([regex]::Matches([string]$p.Value, '[^\x00-\x7F]') | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object { $covered -notcontains $_ })
		if ($loose.Count -gt 0) { $problems += ("'{0}' uses {1}" -f $p.Name, ((@($loose) | ForEach-Object { 'U+{0:X4}' -f [int][char]$_ }) -join ' ')) }
	}
	Write-Result $name 'ascii' $problems
}

if ($failed) { exit 1 }
