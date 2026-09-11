package fileposition

import (
	"unicode/utf16"
	"unicode/utf8"

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
//   - Column.Start is the column of the key's opening quote.
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

	line, col := 1, 1

	// String state (JSON escape-aware). pendingEscape is true right after a
	// lone backslash inside a string, awaiting the character(s) it escapes.
	inString := false
	pendingEscape := false
	var strBuf []byte
	strStartLine := 0
	strStartCol := 0

	// A completed string awaiting classification as a key (":" follows) or a value.
	haveCompletedString := false
	var lastStr string
	lastStrLine := 0
	lastStrColumn := 0

	// A key that has seen its ":" and is awaiting its value.
	havePendingKey := false
	pendingKeyIsPackages := false
	var pendingKey string
	pendingKeyLine := 0
	pendingKeyColumn := 0

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
	entryKeyColumn := 0

	clearPending := func() {
		havePendingKey = false
		pendingKeyIsPackages = false
	}

	// advanceLineCol updates line/col tracking for a single consumed byte.
	// Declared up front so decodeUnicodeEscape (which consumes extra bytes
	// via lookahead) can keep the line/col counters in sync.
	advanceLineCol := func(c byte) {
		if c == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}

	for i := 0; i < len(buf); i++ {
		c := buf[i]

		if inString {
			switch {
			case pendingEscape:
				pendingEscape = false
				switch c {
				case '"', '\\', '/':
					strBuf = append(strBuf, c)
				case 'b':
					strBuf = append(strBuf, '\b')
				case 'f':
					strBuf = append(strBuf, '\f')
				case 'n':
					strBuf = append(strBuf, '\n')
				case 'r':
					strBuf = append(strBuf, '\r')
				case 't':
					strBuf = append(strBuf, '\t')
				case 'u':
					var consumed int
					strBuf, consumed = decodeUnicodeEscape(strBuf, buf[i+1:])
					for range consumed {
						i++
						advanceLineCol(buf[i])
					}
				default:
					// Not a recognized JSON escape; keep the literal character.
					strBuf = append(strBuf, c)
				}
			case c == '\\':
				pendingEscape = true
			case c == '"':
				inString = false
				haveCompletedString = true
				lastStr = string(strBuf)
				lastStrLine = strStartLine
				lastStrColumn = strStartCol
			default:
				strBuf = append(strBuf, c)
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
				strStartCol = col
				strBuf = strBuf[:0]
				pendingEscape = false
				haveCompletedString = false
			case ':':
				if haveCompletedString {
					pendingKey = lastStr
					pendingKeyLine = lastStrLine
					pendingKeyColumn = lastStrColumn
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
					entryKeyColumn = pendingKeyColumn
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
							Start: entryKeyColumn,
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

		advanceLineCol(c)
	}

	return result
}

// decodeUnicodeEscape decodes a \uXXXX escape (and, if immediately followed
// by a matching low surrogate \uXXXX escape, the resulting surrogate pair)
// starting at the beginning of rest, appends the decoded rune to dst, and
// returns the updated buffer along with the number of extra bytes consumed
// from rest (i.e. beyond the 'u' itself, which the caller already consumed).
func decodeUnicodeEscape(dst []byte, rest []byte) ([]byte, int) {
	hi, ok := decodeHex4(rest)
	if !ok {
		return dst, 0
	}
	consumed := 4

	if utf16.IsSurrogate(hi) && len(rest) >= 10 && rest[4] == '\\' && rest[5] == 'u' {
		if lo, ok := decodeHex4(rest[6:]); ok {
			if r := utf16.DecodeRune(hi, lo); r != utf8.RuneError {
				return utf8.AppendRune(dst, r), consumed + 6
			}
		}
	}

	return utf8.AppendRune(dst, hi), consumed
}

// decodeHex4 parses the first 4 bytes of b as a hexadecimal digit sequence
// and returns the resulting rune. ok is false if b is shorter than 4 bytes or
// contains a non-hex-digit character.
func decodeHex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}

	var v rune
	for _, c := range b[:4] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			v |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= rune(c-'A') + 10
		default:
			return 0, false
		}
	}

	return v, true
}

func isJSONWhitespace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}
