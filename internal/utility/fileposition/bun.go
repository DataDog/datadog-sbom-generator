package fileposition

import (
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// InBunLockPackages scans a JSONC-sanitized bun.lock buffer and returns a map
// keyed by the exact package key found inside the top-level "packages" object,
// mapping each key to the source FilePosition of its tuple entry.
//
// The input is expected to be CRLF-normalized and JSONC-sanitized so that
// positions map 1:1 to the raw file. All positions are 1-indexed:
//   - Line.Start / Line.End span the entry's opening line (the key) through the
//     line containing the tuple's closing "]".
//   - Column.Start is the column of the first non-blank character of the entry's
//     opening line (the key's opening quote).
//   - Column.End is the column immediately after the tuple's closing "]".
//
// The returned FilePosition leaves Filename empty; the caller sets it.
//
// The scan is a single pass over the bytes. Brackets and braces only affect the
// combined nesting depth when they occur outside a quoted string; a string is
// closed by a double quote preceded by an even number of consecutive
// backslashes. The "packages" object is matched by its exact quoted token at
// root-object depth, so decoy keys such as "packages/a" (a workspace key) are
// never mistaken for it.
func InBunLockPackages(sanitized []byte) map[string]models.FilePosition {
	result := map[string]models.FilePosition{}

	buf := sanitized
	// Strip a leading UTF-8 BOM if present so columns line up with the raw file.
	if len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF {
		buf = buf[3:]
	}

	// Pre-split lines so Column.Start can reuse the shared first-non-blank helper.
	lines := strings.Split(string(buf), "\n")

	line, col := 1, 1

	// String state (JSON escape-aware).
	inString := false
	backslashes := 0
	var strBuf []byte
	strStartLine := 0

	// A completed string awaiting classification as a key (":" follows) or a value.
	haveCompletedString := false
	var lastStr string
	lastStrLine := 0

	// A key that has seen its ":" and is awaiting its value.
	havePendingKey := false
	pendingKeyIsPackages := false
	var pendingKey string
	pendingKeyLine := 0

	// Combined bracket/brace nesting depth, tracked only outside strings.
	depth := 0

	// Top-level "packages" object tracking.
	foundPackages := false
	inPackages := false
	packagesDepth := -1

	// Current tuple entry tracking.
	inTuple := false
	tupleBaseDepth := 0
	var entryKey string
	entryKeyLine := 0

	clearPending := func() {
		havePendingKey = false
		pendingKeyIsPackages = false
	}

	for _, c := range buf {
		if inString {
			switch {
			case c == '\\':
				backslashes++
			case c == '"':
				if backslashes%2 == 0 {
					// Real closing quote: an even number of preceding backslashes.
					inString = false
					haveCompletedString = true
					lastStr = string(strBuf)
					lastStrLine = strStartLine
				} else {
					// Escaped quote: still inside the string.
					strBuf = append(strBuf, '"')
				}
				backslashes = 0
			default:
				strBuf = append(strBuf, c)
				backslashes = 0
			}
		} else {
			switch c {
			case '"':
				if havePendingKey {
					// Quoted scalar value; the pending key had a non-array value.
					clearPending()
				}
				inString = true
				strStartLine = line
				strBuf = strBuf[:0]
				backslashes = 0
				haveCompletedString = false
			case ':':
				if haveCompletedString {
					pendingKey = lastStr
					pendingKeyLine = lastStrLine
					havePendingKey = true
					pendingKeyIsPackages = !inPackages && !foundPackages && depth == 1 && lastStr == "packages"
					haveCompletedString = false
				}
			case '{':
				if havePendingKey && pendingKeyIsPackages && depth == 1 {
					inPackages = true
					foundPackages = true
					packagesDepth = depth + 1
				}
				clearPending()
				depth++
				haveCompletedString = false
			case '[':
				if havePendingKey && inPackages && !inTuple && depth == packagesDepth {
					inTuple = true
					tupleBaseDepth = depth
					entryKey = pendingKey
					entryKeyLine = pendingKeyLine
				}
				clearPending()
				depth++
				haveCompletedString = false
			case '}':
				depth--
				clearPending()
				haveCompletedString = false
				if inPackages && !inTuple && depth == packagesDepth-1 {
					// The "packages" object has closed; no more entries follow.
					return result
				}
			case ']':
				depth--
				haveCompletedString = false
				if inTuple && depth == tupleBaseDepth {
					result[entryKey] = models.FilePosition{
						Line: models.Position{Start: entryKeyLine, End: line},
						Column: models.Position{
							Start: GetFirstNonEmptyCharacterIndexInLine(lines[entryKeyLine-1]),
							End:   col + 1,
						},
					}
					inTuple = false
				}
				clearPending()
			case ',':
				clearPending()
				haveCompletedString = false
			default:
				if !isJSONWhitespace(c) {
					// Any other value start (number, true/false/null): consume pending.
					clearPending()
					haveCompletedString = false
				}
			}
		}

		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}

	return result
}

func isJSONWhitespace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}
