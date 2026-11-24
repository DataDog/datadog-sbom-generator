package fileposition

import (
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func BytesToLines(data []byte) []string {
	str := string(data)
	if strings.IndexByte(str, '\r') < 0 {
		return strings.Split(str, "\n")
	}

	count := 1
	for i := 0; i < len(str); i++ {
		if str[i] == '\r' {
			count++
			if i+1 < len(str) && str[i+1] == '\n' {
				i++
			}
		} else if str[i] == '\n' {
			count++
		}
	}

	lines := make([]string, 0, count)
	start := 0
	for i := 0; i < len(str); i++ {
		if str[i] == '\r' {
			lines = append(lines, str[start:i])
			if i+1 < len(str) && str[i+1] == '\n' {
				i++
			}
			start = i + 1
		} else if str[i] == '\n' {
			lines = append(lines, str[start:i])
			start = i + 1
		}
	}
	lines = append(lines, str[start:])

	return lines
}

func extractPositionFromLine(linePosition int, line string, str string) *models.FilePosition {
	columnStart := strings.Index(line, str) + 1
	columnEnd := columnStart + len(str)

	return &models.FilePosition{
		Line:   models.Position{Start: linePosition, End: linePosition},
		Column: models.Position{Start: columnStart, End: columnEnd},
	}
}

func ExtractStringPositionInBlock(block []string, str string, blockStartLine int) *models.FilePosition {
	if len(str) == 0 {
		return nil
	}

	return ExtractDelimitedStringPositionInBlock(block, str, blockStartLine, "", "")
}

func ExtractDelimitedStringPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	for i, line := range block {
		search := prefix + str + suffix
		if strings.Contains(line, search) {
			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}

func ExtractDelimitedRegexpPositionInBlock(block []string, str string, blockStartLine int, prefix string, suffix string) *models.FilePosition {
	// We name the group we are looking for in order to identify it after in the matches
	// This is required due to the fact that prefix and suffix could also be regex and contain other groups
	term := "(?P<term>" + str + ")"
	regex := cachedregexp.MustCompile(prefix + term + suffix)
	for i, line := range block {
		matches := regex.FindStringSubmatch(line)
		if len(matches) > 0 {
			// Replace regexp with captured value
			// We use the named group to identify the captured value
			str = matches[slices.Index(regex.SubexpNames(), "term")]

			return extractPositionFromLine(blockStartLine+i, line, str)
		}
	}

	return nil
}
