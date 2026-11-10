package java

// SetMaxNestedArchiveSize overrides the nested archive size limit and returns
// a function restoring the previous value.
func SetMaxNestedArchiveSize(size uint64) func() {
	previous := maxNestedArchiveSize
	maxNestedArchiveSize = size

	return func() { maxNestedArchiveSize = previous }
}

// SetMaxNestedArchiveBudget overrides the cumulative nested archive budget and
// returns a function restoring the previous value.
func SetMaxNestedArchiveBudget(size uint64) func() {
	previous := maxNestedArchiveBudget
	maxNestedArchiveBudget = size

	return func() { maxNestedArchiveBudget = previous }
}
