package fileposition

import (
	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
)

var wordRe = cachedregexp.MustCompile(`[^\s\r\n]+`)

func GetFirstNonEmptyCharacterIndexInLine(line string) int {
	firstWord := wordRe.FindStringIndex(line)
	if firstWord != nil {
		return firstWord[0] + 1
	}

	return -1
}

func GetLastNonEmptyCharacterIndexInLine(line string) int {
	words := wordRe.FindAllStringIndex(line, -1)
	if words != nil {
		lastWord := words[len(words)-1]

		return lastWord[1] + 1
	}

	return -1
}
