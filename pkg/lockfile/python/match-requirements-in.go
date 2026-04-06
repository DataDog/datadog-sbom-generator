package python

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m RequirementsInMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	base := filepath.Base(f.Path())
	inFile := strings.TrimSuffix(base, ".txt") + ".in"

	sourceFile, err := f.Open(inFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}

	return sourceFile, nil
}

func (m RequirementsInMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// Build index: normalized name → slice of indices into packages
	packagesByName := make(map[string][]int, len(packages))
	for i, pkg := range packages {
		key := normalizedRequirementName(pkg.Name)
		packagesByName[key] = append(packagesByName[key], i)
	}

	// claimed tracks which package indices have already been mapped to a .in line.
	// This prevents a later duplicate-name entry (e.g. two marker-specific pins for
	// the same package) from overwriting a location that was already correctly set.
	claimed := make(map[int]bool, len(packages))

	for index, line := range lines {
		lineNumber := index + 1
		trimmedLine := strings.TrimSpace(line)

		// Skip comments, blanks, options (-r, --index-url, etc.), and bare URLs.
		// Do NOT skip PEP 508 direct references like "pkg @ https://..." — those start
		// with the package name, not a URL scheme.
		if trimmedLine == "" || isComment(line) || strings.HasPrefix(trimmedLine, "-") ||
			strings.HasPrefix(trimmedLine, "http://") || strings.HasPrefix(trimmedLine, "https://") {
			continue
		}

		rawName := extractPackageNameFromRequirementsLine(trimmedLine)
		if rawName == "" {
			continue
		}

		normalizedName := normalizedRequirementName(rawName)

		indices, ok := packagesByName[normalizedName]
		if !ok {
			continue
		}

		// When the same package name appears more than once in the .in file
		// (e.g. marker-specific pins for different Python versions), select which
		// packages this line should claim using a preference order:
		//   1. Unclaimed packages whose resolved version appears literally in this line
		//      (handles exact-pinned duplicates like "requests==2.0" / "requests==3.5").
		//   2. Any remaining unclaimed packages (handles range constraints).
		//   3. Skip — all candidates are already claimed by an earlier line.
		var toUpdate []int
		for _, idx := range indices {
			if !claimed[idx] && packages[idx].Version != "" && strings.Contains(trimmedLine, packages[idx].Version) {
				toUpdate = append(toUpdate, idx)
			}
		}
		if len(toUpdate) == 0 {
			for _, idx := range indices {
				if !claimed[idx] {
					toUpdate = append(toUpdate, idx)
				}
			}
		}
		if len(toUpdate) == 0 {
			continue
		}

		startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

		for _, key := range toUpdate {
			claimed[key] = true

			packages[key].BlockLocation = models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: startColumn, End: endColumn},
				Filename: sourceFile.Path(),
			}

			nameLocation := fileposition.ExtractStringPositionInBlock([]string{line}, rawName, lineNumber)
			if nameLocation != nil {
				nameLocation.Filename = sourceFile.Path()
				packages[key].NameLocation = nameLocation
			}

			versionLocation := fileposition.ExtractStringPositionInBlock([]string{line}, packages[key].Version, lineNumber)
			if versionLocation != nil {
				versionLocation.Filename = sourceFile.Path()
				packages[key].VersionLocation = versionLocation
			} else {
				// Nil out stale version location from the .txt file to avoid
				// mixed file references (block in .in, version in .txt)
				packages[key].VersionLocation = nil
			}

			packages[key].IsDirect = true
		}
	}

	return nil
}

// extractPackageNameFromRequirementsLine extracts the raw package name from a
// requirements line, before any version specifier or extras marker.
// Example: "typing_extensions>=4.0" → "typing_extensions"
// Example: "redis[hiredis]==3.5.3" → "redis"
func extractPackageNameFromRequirementsLine(line string) string {
	for i, c := range line {
		// Stop at version specifiers, extras, direct-reference (@), or environment
		// marker separator (;).  The semicolon must be checked before '=' so that a
		// line like "aa; python_version=='2.7'" returns "aa" rather than
		// "aa; python_version".
		if c == ';' || c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '[' || c == '@' {
			return strings.TrimSpace(line[:i])
		}
	}

	return strings.TrimSpace(line)
}

var _ lockfile.Matcher = RequirementsInMatcher{}
