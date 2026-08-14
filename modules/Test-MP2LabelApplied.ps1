function Test-MP2LabelApplied {
	[CmdletBinding()] param( [Parameter(Mandatory)][psobject]$Spec )
	$ident = Get-MountIdentity $Spec
	if ([string]::IsNullOrWhiteSpace($Spec.Server) -or [string]::IsNullOrWhiteSpace($ident)) { return $false }
	# No label desired -> nothing to enforce
	if ([string]::IsNullOrWhiteSpace($Spec.Label)) { return $true }
	foreach ($name in (Get-MP2KeyNames $Spec)) {
		$p = Join-Path $RegMP2 $name
		if (Test-Path -LiteralPath $p) {
			try { $val = (Get-ItemProperty -LiteralPath $p -ErrorAction Stop).'_LabelFromReg'; if ($val -and ($val -eq $Spec.Label)) { return $true } } catch {}
			# Sibling with trailing '#' (some builds materialize it)
			$s = $p + '#'
			if (Test-Path -LiteralPath $s) { try { $val2 = (Get-ItemProperty -LiteralPath $s -ErrorAction Stop).'_LabelFromReg'; if ($val2 -and ($val2 -eq $Spec.Label)) { return $true } } catch {} }
		}
	}
	return $false
}
