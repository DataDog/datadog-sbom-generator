package fileposition

func isRegexpWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\f' || b == '\r'
}

func GetFirstNonEmptyCharacterIndexInLine(line string) int {
	for i := range len(line) {
		if !isRegexpWhitespace(line[i]) {
			return i + 1
		}
	}

	return -1
}

func GetLastNonEmptyCharacterIndexInLine(line string) int {
	for i := len(line) - 1; i >= 0; i-- {
		if !isRegexpWhitespace(line[i]) {
			return i + 2
		}
	}

	return -1
}
