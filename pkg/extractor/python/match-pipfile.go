package python

import (
	"io"
	"strings"
	"unicode"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m PipfileMatcher) GetSourceFile(depFile extractor.DepFile) (extractor.DepFile, error) {
	return depFile.Open("Pipfile")
}

func (m PipfileMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)
	var inDevDepTable bool

	for index, line := range lines {
		lineNumber := index + 1

		if isTable(line) {
			inDevDepTable = isDevTable(line)
			continue
		}

		manifestKeys, ok := tomlLineKeys(line)
		if !ok {
			continue
		}

		for key, pkg := range packages {
			lowerName := strings.ToLower(pkg.Name)
			// Compare against the full TOML key(s) rather than a substring match, otherwise a
			// package like "requests" would match a line declaring "requests-oauthlib".
			manifestKey, ok := findManifestKey(manifestKeys, lowerName)
			if !ok {
				continue
			}

			lowerLine := strings.ToLower(line)
			startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
			endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

			packages[key].LocationRole = models.LocationRoleManifest
			packages[key].BlockLocation = models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: startColumn, End: endColumn},
				Filename: sourceFile.Path(),
			}

			// Search within the matched key's own anchor text rather than the whole line, so
			// that a package like "requests" resolves to its own entry instead of the
			// occurrence inside a sibling entry such as "requests-oauthlib" declared in the
			// same inline array.
			anchor := strings.ToLower(manifestKey.raw)
			searchLine, columnOffset := lowerLine, 0
			if anchorOffset := strings.Index(lowerLine, anchor); anchorOffset != -1 {
				searchLine, columnOffset = anchor, anchorOffset
			}

			nameLocation := fileposition.ExtractStringPositionInBlock([]string{searchLine}, lowerName, lineNumber)
			if nameLocation != nil {
				nameLocation.Column.Start += columnOffset
				nameLocation.Column.End += columnOffset
				nameLocation.Filename = sourceFile.Path()
				packages[key].NameLocation = nameLocation
			}

			versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, ".*", lineNumber, "=\\s*\"", "\"")
			if versionLocation != nil {
				versionLocation.Filename = sourceFile.Path()
				packages[key].VersionLocation = versionLocation
			}

			packages[key].IsDirect = true

			if inDevDepTable {
				packages[key].DepGroups = append(packages[key].DepGroups, "dev")
			}
		}
	}

	return nil
}

func isTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")
}

// manifestKey is a package name found on a manifest line, together with the exact substring of
// the line ("raw") that it was extracted from. For a "key = value" line or a standalone PEP 621
// array item, raw is the whole trimmed line. For an item inside an inline PEP 621 array, raw is
// just that item's own token (e.g. `"requests"`), so callers can search for the name within raw
// instead of the full line and avoid matching a sibling entry with a shared prefix, e.g.
// "requests-oauthlib" on the same line as "requests".
type manifestKey struct {
	name string
	raw  string
}

// findManifestKey looks up lowerName among keys, comparing case-insensitively.
func findManifestKey(keys []manifestKey, lowerName string) (manifestKey, bool) {
	for _, k := range keys {
		if strings.ToLower(k.name) == lowerName {
			return k, true
		}
	}

	return manifestKey{}, false
}

// tomlLineKeys extracts the package name(s) to match from a manifest line. It handles a
// "key = value" TOML line (Pipfile/Poetry), a PEP 621 dependency array item on its own line such
// as `"requests==2.28.0",`, and a PEP 621 inline dependency array such as
// `dependencies = ["requests==2.28.0", "flask>=2.0"]` (pyproject.toml `dependencies = [...]`).
// It is not a full TOML/PEP 508 parser: it only isolates the name(s) so packages are matched
// exactly instead of via substring search.
func tomlLineKeys(line string) ([]manifestKey, bool) {
	line = stripTrailingComment(line)
	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" {
		return nil, false
	}

	if keys, ok := pep621InlineArrayKeys(trimmedLine); ok {
		return keys, true
	}

	if name, ok := pep621ArrayItemName(trimmedLine); ok {
		return []manifestKey{{name: name, raw: trimmedLine}}, true
	}

	key, _, found := strings.Cut(trimmedLine, "=")
	if !found {
		return nil, false
	}

	key = strings.Trim(strings.TrimSpace(key), `"'`)
	if key == "" {
		return nil, false
	}

	return []manifestKey{{name: key, raw: trimmedLine}}, true
}

// stripTrailingComment removes a trailing TOML comment (a "#" and everything after it) from line,
// ignoring any "#" that appears inside a quoted string. This lets a commented dependency entry
// such as `"requests>=2", # needed by API` still be recognized: without stripping the comment
// first, pep621ArrayItemName would see trailing content after the closing quote and reject the
// line as an unrecognized token.
func stripTrailingComment(line string) string {
	var quote byte

	for i := 0; i < len(line); i++ {
		c := line[i]

		if quote != 0 {
			if quote == '"' && c == '\\' {
				i++
				continue
			}

			if c == quote {
				quote = 0
			}

			continue
		}

		switch c {
		case '"', '\'':
			quote = c
		case '#':
			return line[:i]
		}
	}

	return line
}

// pep621InlineArrayKeys extracts package names from a PEP 621 dependency array declared inline
// on a single line, e.g. `dependencies = ["requests==2.28.0", "flask>=2.0"]`. It requires the
// value assigned to the key to be a bracketed list closed on the same line (nothing else on the
// line besides an optional trailing comma), which excludes plain "key = value" lines, the opening
// line of a multiline array (`dependencies = [`), and inline tables containing a nested array
// such as `requests = { version = "^2", extras = ["socks"] }` (there the value starts with "{",
// not "[").
func pep621InlineArrayKeys(trimmedLine string) ([]manifestKey, bool) {
	key, value, found := strings.Cut(trimmedLine, "=")
	if !found || strings.TrimSpace(key) == "" {
		return nil, false
	}

	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), ","))
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, false
	}

	var keys []manifestKey
	for _, item := range splitTopLevelArrayItems(value[1 : len(value)-1]) {
		item = strings.TrimSpace(item)
		if name, ok := pep621ArrayItemName(item); ok {
			keys = append(keys, manifestKey{name: name, raw: item})
		}
	}

	return keys, len(keys) > 0
}

// splitTopLevelArrayItems splits the inside of a TOML array on commas, ignoring commas that appear
// inside quoted strings. This preserves PEP 508 requirement specifiers that contain a comma as part
// of a version constraint, e.g. `"urllib3>=1.26,<3"`, which a naive strings.Split(s, ",") would cut
// in half. Escaped quotes inside a double-quoted string (e.g. `"requests; python_version <
// \"3.12\""`) are skipped rather than treated as the string terminator.
func splitTopLevelArrayItems(inner string) []string {
	var items []string
	var current strings.Builder
	var quote byte

	for i := 0; i < len(inner); i++ {
		c := inner[i]

		if quote != 0 {
			current.WriteByte(c)
			if quote == '"' && c == '\\' && i+1 < len(inner) {
				i++
				current.WriteByte(inner[i])

				continue
			}

			if c == quote {
				quote = 0
			}

			continue
		}

		switch c {
		case '"', '\'':
			quote = c
			current.WriteByte(c)
		case ',':
			items = append(items, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}

	if strings.TrimSpace(current.String()) != "" {
		items = append(items, current.String())
	}

	return items
}

// pep621ArrayItemName extracts the package name from a standalone quoted dependency-array item,
// e.g. `"requests==2.28.0",` or `'flask[async]>=2.0'`. It returns false for anything that isn't
// a single quoted token on the line, including quoted `"key" = "value"` lines, which still need
// to go through the key = value path in tomlLineKeys.
func pep621ArrayItemName(trimmedLine string) (string, bool) {
	line := strings.TrimSuffix(trimmedLine, ",")
	if len(line) < 2 {
		return "", false
	}

	quote := line[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	closeIdx := findClosingQuote(line[1:], quote)
	if closeIdx == -1 {
		return "", false
	}
	closeIdx++

	if strings.TrimSpace(line[closeIdx+1:]) != "" {
		return "", false
	}

	spec := line[1:closeIdx]
	end := strings.IndexFunc(spec, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r))
	})
	name := spec
	if end != -1 {
		name = spec[:end]
	}
	name = strings.TrimSpace(name)

	return name, name != ""
}

// findClosingQuote returns the index of the first unescaped occurrence of quote in s. Only
// double-quoted TOML strings support backslash escapes, so a backslash inside a single-quoted
// (literal) string is treated as a literal character rather than an escape.
func findClosingQuote(s string, quote byte) int {
	for i := 0; i < len(s); i++ {
		if quote == '"' && s[i] == '\\' {
			i++
			continue
		}

		if s[i] == quote {
			return i
		}
	}

	return -1
}

func isDevTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return trimmedLine == "[tool.poetry.dev-dependencies]" || trimmedLine == "[tool.poetry.group.dev.dependencies]"
}

var _ extractor.Matcher = PipfileMatcher{}
