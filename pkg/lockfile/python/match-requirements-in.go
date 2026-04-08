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
		//   1. Unclaimed packages whose resolved version exactly matches the pin on
		//      this line (the version after "==").  Exact comparison avoids substring
		//      false-positives (e.g. "2.0" matching inside "12.0" or in marker text).
		//   2. ONE unclaimed package in fallback, for range/URL constraints where no
		//      exact pin is present.  Claiming only one means N duplicate-name lines
		//      distribute across N resolved packages instead of collapsing onto line 1.
		//   3. Skip — all candidates are already claimed by an earlier line.
		var toUpdate []int
		pinnedVersion := extractPinnedVersionFromLine(trimmedLine)
		if pinnedVersion != "" {
			for _, idx := range indices {
				if !claimed[idx] && packages[idx].Version == pinnedVersion {
					toUpdate = append(toUpdate, idx)
				}
			}
		}
		if len(toUpdate) == 0 {
			for _, idx := range indices {
				if !claimed[idx] {
					toUpdate = append(toUpdate, idx)
					break // one per line — prevents all same-name packages collapsing onto the first range line
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
		if c == '#' || c == ';' || c == '=' || c == '>' || c == '<' || c == '!' || c == '~' || c == '[' || c == '@' {
			return strings.TrimSpace(line[:i])
		}
	}

	return strings.TrimSpace(line)
}

// extractPinnedVersionFromLine returns the version string following a bare "=="
// operator in a requirements specifier, or "" if no exact pin is present.
// Environment markers (everything after ";") are stripped first so that
// expressions like python_version=='3.11' in marker text are not mistaken for
// a version pin.
//
// Examples:
//
//	"requests==2.32.3"                     → "2.32.3"
//	"requests[security]==2.32.3"           → "2.32.3"
//	"requests==2.32.3; python_version>='3'" → "2.32.3"
//	"foo==12.0"                            → "12.0"  (not "2.0")
//	"requests>=2.0"                        → ""
//	"requests!=2.0"                        → ""
//	"requests===2.0"                       → ""  (arbitrary equality; treated as no pin)
func extractPinnedVersionFromLine(line string) string {
	// Strip environment markers so python_version=='x' is not treated as a pin.
	if i := strings.IndexByte(line, ';'); i != -1 {
		line = line[:i]
	}
	for i := range len(line) - 1 {
		if line[i] == '=' && line[i+1] == '=' && (i == 0 || line[i-1] != '!') && (i+2 >= len(line) || line[i+2] != '=') {
			rest := strings.TrimSpace(line[i+2:])
			// Version token ends at whitespace, comma, semicolon, or extras bracket.
			if end := strings.IndexAny(rest, " \t,;["); end != -1 {
				return rest[:end]
			}

			return rest
		}
	}

	return ""
}

var _ lockfile.Matcher = RequirementsInMatcher{}
