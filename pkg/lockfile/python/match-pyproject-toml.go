package python

import (
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m PyprojectTOMLMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	var parsed pyprojectTOML
	if err = toml.Unmarshal(content, &parsed); err != nil {
		return err
	}

	pkgNameToGroups := buildDirectPkgs(parsed)

	if len(pkgNameToGroups) == 0 {
		return nil
	}

	rawLines := fileposition.BytesToLines(content)
	lowerLines := make([]string, len(rawLines))
	for i, line := range rawLines {
		lowerLines[i] = strings.ToLower(line)
	}

	for key, pkg := range packages {
		lowerName := strings.ToLower(pkg.Name)
		groups, isDirect := pkgNameToGroups[lowerName]
		if !isDirect {
			continue
		}

		packages[key].IsDirect = true
		packages[key].DepGroups = append(packages[key].DepGroups, groups...)

		for index, lowerLine := range lowerLines {
			if !isPoetryDepLine(lowerLine, lowerName) && !isPEP621DepLine(lowerLine, lowerName) {
				continue
			}

			lineNumber := index + 1
			startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(lowerLine)
			endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(lowerLine)

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

			versionLocation := extractVersionLocation(lowerLine, lineNumber, sourceFile.Path())
			if versionLocation != nil {
				packages[key].VersionLocation = versionLocation
			}

			break
		}
	}

	return nil
}

// buildDirectPkgs returns a map of normalized package name → dep groups from all
// supported pyproject.toml formats (Poetry and PEP 621).
//
// Poetry dependency specification: https://python-poetry.org/docs/dependency-specification/
// Poetry dependency groups:        https://python-poetry.org/docs/managing-dependencies/
// PEP 621 project metadata:        https://peps.python.org/pep-0621/
func buildDirectPkgs(parsed pyprojectTOML) map[string][]string {
	pkgNameToGroups := make(map[string][]string)

	// Poetry: [tool.poetry.dependencies]
	// https://python-poetry.org/docs/pyproject/#dependencies-and-dependency-groups
	for pkgName := range parsed.Tool.Poetry.Dependencies {
		pkgNameToGroups[strings.ToLower(pkgName)] = nil
	}

	// Poetry: [tool.poetry.dev-dependencies] (legacy format, superseded by groups)
	// https://python-poetry.org/docs/managing-dependencies/#dependency-groups
	for pkgName := range parsed.Tool.Poetry.DevDependencies {
		lowerPkgName := strings.ToLower(pkgName)
		pkgNameToGroups[lowerPkgName] = appendGroup(pkgNameToGroups[lowerPkgName], "dev")
	}

	// Poetry: [tool.poetry.group.X.dependencies]
	// https://python-poetry.org/docs/managing-dependencies/#dependency-groups
	for groupName, group := range parsed.Tool.Poetry.Groups {
		for pkgName := range group.Dependencies {
			lowerPkgName := strings.ToLower(pkgName)
			pkgNameToGroups[lowerPkgName] = appendGroup(pkgNameToGroups[lowerPkgName], groupName)
		}
	}

	// PEP 621: [project] dependencies = [...]
	// https://peps.python.org/pep-0621/#dependencies-optional-dependencies
	for _, spec := range parsed.Project.Dependencies {
		pkgName := extractPEP508Name(spec)
		if pkgName != "" {
			pkgNameToGroups[pkgName] = nil
		}
	}

	// PEP 621: [project.optional-dependencies]
	// https://peps.python.org/pep-0621/#dependencies-optional-dependencies
	for groupName, specs := range parsed.Project.OptionalDependencies {
		for _, spec := range specs {
			pkgName := extractPEP508Name(spec)
			if pkgName != "" {
				pkgNameToGroups[pkgName] = appendGroup(pkgNameToGroups[pkgName], groupName)
			}
		}
	}

	// Sort groups for deterministic output — Go map iteration order is random,
	// so without sorting DepGroups can vary between runs producing unstable SBOMs.
	for pkgName, groups := range pkgNameToGroups {
		sort.Strings(groups)
		pkgNameToGroups[pkgName] = groups
	}

	return pkgNameToGroups
}

// appendGroup appends groupName to groups, deduplicating.
func appendGroup(groups []string, groupName string) []string {
	if slices.Contains(groups, groupName) {
		return groups
	}

	return append(groups, groupName)
}

// extractPEP508Name returns the normalized package name from a PEP 508 dependency
// specifier string such as "numpy>=1.24", "requests[security]>=2.28", or "black".
// Applies PEP 503 normalization so that "typing_extensions" and "typing-extensions"
// resolve to the same key as the canonicalized lockfile name.
// https://peps.python.org/pep-0508/
// https://peps.python.org/pep-0503/#normalized-names
func extractPEP508Name(spec string) string {
	for i, c := range spec {
		switch c {
		case '[', '>', '<', '=', '!', '~', '@', ';', ' ', '\t':
			return normalizedRequirementName(spec[:i])
		}
	}

	return normalizedRequirementName(spec)
}

// extractVersionLocation tries to find the version value on the given line, trying
// Poetry key=value format first, then PEP 621 array-entry format.
// Environment markers (after `;`) are stripped before the PEP 621 search to avoid
// false matches on marker comparators like `python_version < "3.10"`.
func extractVersionLocation(line string, lineNumber int, filename string) *models.FilePosition {
	// Poetry: name = "version"
	loc := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, ".*", lineNumber, `=\s*"`, `"`)
	if loc != nil {
		loc.Filename = filename
		return loc
	}

	// PEP 621: strip environment markers before matching version specifier
	depPart, _, _ := strings.Cut(line, ";")

	loc = fileposition.ExtractDelimitedRegexpPositionInBlock([]string{depPart}, `[^",\s]+`, lineNumber, `[><=!~]{1,3}`, ``)
	if loc != nil {
		loc.Filename = filename
		return loc
	}

	return nil
}

// isPoetryDepLine reports whether line is a Poetry TOML key=value dependency entry for pkgName.
// Matches `pkgName =` or `pkgName=` at the start of the line (after whitespace),
// preventing short names like "py" from matching "requires-python".
func isPoetryDepLine(line, pkgName string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, pkgName) {
		return false
	}
	rest := trimmed[len(pkgName):]

	return strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "\t")
}

// isPEP621DepLine reports whether line is a PEP 621 array dependency entry for pkgName.
// Matches `"pkgName` — package name immediately following an opening quote.
func isPEP621DepLine(line, pkgName string) bool {
	return strings.Contains(line, `"`+pkgName)
}

var _ lockfile.Matcher = PyprojectTOMLMatcher{}
