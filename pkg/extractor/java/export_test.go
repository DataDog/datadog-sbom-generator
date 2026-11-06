package java

// SetMaxNestedArchiveSize overrides the nested archive size limit and returns
// a function restoring the previous value.
func SetMaxNestedArchiveSize(size uint64) func() {
	previous := maxNestedArchiveSize
	maxNestedArchiveSize = size

	return func() { maxNestedArchiveSize = previous }
}
