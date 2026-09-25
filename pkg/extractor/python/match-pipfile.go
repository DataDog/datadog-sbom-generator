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

	// In poetry, if the table name is [tool.poetry.dev-dependencies] or [tool.poetry.group.dev.dependencies],
	// then the dependencies under this table are dev dependencies.
	// Otherwise, they are regular dependencies
	var inDevDepTable bool

	for index, line := range lines {
		lineNumber := index + 1

		// if this is the start of a new table, check if it's a table that can contain dev dependencies
		if isTable(line) {
			inDevDepTable = isDevTable(line)
			continue
		}

		manifestKeys, ok := tomlLineKeys(line)
		if !ok {
			continue
		}

		for key, pkg := range packages {
			// There are some libraries that use upper case names, but their name is resolve as lower case (i.e. Django != django)
			lowerName := strings.ToLower(pkg.Name)
			// Compare against the full TOML key(s) rather than a substring match, otherwise a
			// package like "requests" would match a line declaring "requests-oauthlib".
			if !containsLower(manifestKeys, lowerName) {
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

			nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerName, lineNumber)
			if nameLocation != nil {
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

// isTable checks if the line is a table in the Pipfile format.
func isTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]")
}

// tomlLineKeys extracts the package name(s) to match from a manifest line. It handles a
// "key = value" TOML line (Pipfile/Poetry), a PEP 621 dependency array item on its own line such
// as `"requests==2.28.0",`, and a PEP 621 inline dependency array such as
// `dependencies = ["requests==2.28.0", "flask>=2.0"]` (pyproject.toml `dependencies = [...]`).
// It is not a full TOML/PEP 508 parser: it only isolates the name(s) so packages are matched
// exactly instead of via substring search.
func tomlLineKeys(line string) ([]string, bool) {
	trimmedLine := strings.TrimSpace(line)
	if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
		return nil, false
	}

	if names, ok := pep621InlineArrayNames(trimmedLine); ok {
		return names, true
	}

	if name, ok := pep621ArrayItemName(trimmedLine); ok {
		return []string{name}, true
	}

	key, _, found := strings.Cut(trimmedLine, "=")
	if !found {
		return nil, false
	}

	key = strings.Trim(strings.TrimSpace(key), `"'`)
	if key == "" {
		return nil, false
	}

	return []string{key}, true
}

// containsLower reports whether lowerName is present in names, comparing case-insensitively.
func containsLower(names []string, lowerName string) bool {
	for _, name := range names {
		if strings.ToLower(name) == lowerName {
			return true
		}
	}

	return false
}

// pep621InlineArrayNames extracts package names from a PEP 621 dependency array declared inline
// on a single line, e.g. `dependencies = ["requests==2.28.0", "flask>=2.0"]`. It requires the value
// assigned to the key to be a bracketed list closed on the same line (nothing else on the line
// besides an optional trailing comma), which excludes plain "key = value" lines, the opening line
// of a multiline array (`dependencies = [`), and inline tables containing a nested array such as
// `requests = { version = "^2", extras = ["socks"] }` (there the value starts with "{", not "[").
func pep621InlineArrayNames(trimmedLine string) ([]string, bool) {
	key, value, found := strings.Cut(trimmedLine, "=")
	if !found || strings.TrimSpace(key) == "" {
		return nil, false
	}

	value = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(value), ","))
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, false
	}

	var names []string
	for _, item := range splitTopLevelArrayItems(value[1 : len(value)-1]) {
		if name, ok := pep621ArrayItemName(strings.TrimSpace(item)); ok {
			names = append(names, name)
		}
	}

	return names, len(names) > 0
}

// splitTopLevelArrayItems splits the inside of a TOML array on commas, ignoring commas that appear
// inside quoted strings. This preserves PEP 508 requirement specifiers that contain a comma as part
// of a version constraint, e.g. `"urllib3>=1.26,<3"`, which a naive strings.Split(s, ",") would cut
// in half.
func splitTopLevelArrayItems(inner string) []string {
	var items []string
	var current strings.Builder
	var quote byte

	for i := range len(inner) {
		c := inner[i]

		if quote != 0 {
			current.WriteByte(c)
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
// to go through the key = value path in tomlLineKey.
func pep621ArrayItemName(trimmedLine string) (string, bool) {
	line := strings.TrimSuffix(trimmedLine, ",")
	if len(line) < 2 {
		return "", false
	}

	quote := line[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}

	closeIdx := strings.IndexByte(line[1:], quote)
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

// isDevTable checks if the line is a dev dependency table for Poetry, since the implementation is shared as both tools use toml files.
func isDevTable(line string) bool {
	trimmedLine := strings.TrimSpace(strings.ToLower(line))
	return trimmedLine == "[tool.poetry.dev-dependencies]" || trimmedLine == "[tool.poetry.group.dev.dependencies]"
}

var _ extractor.Matcher = PipfileMatcher{}
