# What a failed mapping attempt is called. 1219 is not a failure in the sense the
# other codes are: both server identities the host offers are spoken for, the
# mount itself is sound, and the next poll brings it up by itself the moment one
# of them is given up. Calling that "mapping failed" sends the user looking for a
# fault that is not there, so it gets a name that says what is actually happening.
function Get-MapFailureStatus([int]$Rc) {
	if ($Rc -eq 1219) { return 'blocked' }
	return 'failed'
}