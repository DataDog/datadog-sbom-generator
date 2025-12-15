package sliceutil

// Reverse reverses a slice in place
func Reverse[T any](s []T) {
	for i := range len(s) / 2 {
		j := len(s) - 1 - i
		s[i], s[j] = s[j], s[i]
	}
}
