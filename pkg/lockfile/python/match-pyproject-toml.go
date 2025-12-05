package python

import (
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (m PyprojectTOMLMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourcefile lockfile.DepFile, packages []lockfile.PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	lines := fileposition.BytesToLines(content)

	// Track which table we're in to determine if dependencies are dev dependencies
	var inDevDepTable bool
	var inPEP621DepsArray bool
	var inPEP621DevDepsArray bool

	for index, line := range lines {
		lineNumber := index + 1

		// Check if we're entering a new table
		if isTable(line) {
			trimmedLine := strings.TrimSpace(strings.ToLower(line))
			// Poetry format tables
			inDevDepTable = isDevTable(line)
			// PEP 621 format tables
			inPEP621DepsArray = false
			inPEP621DevDepsArray = false

			// Check for PEP 621 [project.optional-dependencies.dev]
			// Only mark as dev if the section is explicitly "dev"
			if strings.HasPrefix(trimmedLine, "[project.optional-dependencies.dev") {
				inPEP621DevDepsArray = true
			}
		}

		// Check if we're in a PEP 621 dependencies array
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "dependencies") && strings.Contains(trimmedLine, "[") {
			inPEP621DepsArray = true
			inPEP621DevDepsArray = false
		}

		// Check for PEP 621 optional dependencies in format: dev = [...]
		// Only mark as dev if the key is explicitly "dev"
		if strings.HasPrefix(trimmedLine, "dev") && strings.Contains(trimmedLine, "[") {
			inPEP621DevDepsArray = true
			inPEP621DepsArray = false
		}

		// Check if we've exited an array
		if inPEP621DepsArray || inPEP621DevDepsArray {
			if strings.Contains(trimmedLine, "]") && !strings.Contains(trimmedLine, "[") {
				inPEP621DepsArray = false
				inPEP621DevDepsArray = false
			}
		}

		for key, pkg := range packages {
			lowerLine := strings.ToLower(line)
			lowerName := strings.ToLower(pkg.Name)

			// Skip if the package name is not in this line
			if !strings.Contains(lowerLine, lowerName) {
				continue
			}

			// Handle PEP 621 format: "package==version" or "package>=version"
			if inPEP621DepsArray || inPEP621DevDepsArray {
				if matched := matchPEP621Dependency(lowerName, line, lineNumber, sourcefile, key, packages); matched {
					if inPEP621DevDepsArray {
						packages[key].DepGroups = append(packages[key].DepGroups, "dev")
					}

					continue
				}
			}

			// Handle Poetry/Pipfile format: package = "version"
			matchPoetryDependency(lowerLine, lowerName, line, lineNumber, sourcefile, key, packages, inDevDepTable)
		}
	}

	return nil
}

// matchPEP621Dependency matches dependencies in PEP 621 format following PEP 508 spec
// Supports: "package", "package[extras]", "package==version", "package[extras]>=version"
func matchPEP621Dependency(lowerName, originalLine string, lineNumber int, sourcefile lockfile.DepFile, key int, packages []lockfile.PackageDetails) bool {
	// PEP 621 format uses strings like "flask==0.12", "ray>=2.4.0", "requests", "uvicorn[standard]"
	// The package name and optional version are in a single quoted string
	re := cachedregexp.MustCompile(`["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(originalLine, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		depString := match[1]
		lowerDepString := strings.ToLower(depString)

		// Check if this dependency string contains our package name
		if !strings.HasPrefix(lowerDepString, lowerName) {
			continue
		}

		// Parse the dependency string to extract name and version
		// Support formats: package, package[extras], package==version, package[extras]>=version, etc.
		// PEP 508 spec: name[extras] (==|>=|<=|~=|!=|>|<)version
		versionRe := cachedregexp.MustCompile(`^([a-zA-Z0-9_-]+)(\[[^\]]+\])?(==|>=|<=|~=|!=|>|<)?(.*)$`)
		versionMatches := versionRe.FindStringSubmatch(depString)

		if len(versionMatches) >= 2 {
			parsedName := versionMatches[1]
			extras := versionMatches[2]          // e.g., "[standard]" or empty
			versionOperator := versionMatches[3] // e.g., "==" or empty
			version := versionMatches[4]         // e.g., "0.12" or empty

			// Verify the parsed name matches our package (case-insensitive)
			if strings.ToLower(parsedName) != lowerName {
				continue
			}

			// Calculate positions in the original line
			startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(originalLine)
			endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(originalLine)

			packages[key].BlockLocation = models.FilePosition{
				Line:     models.Position{Start: lineNumber, End: lineNumber},
				Column:   models.Position{Start: startColumn, End: endColumn},
				Filename: sourcefile.Path(),
			}

			// Find the position of the package name within the string
			quoteStart := strings.Index(originalLine, match[0])
			if quoteStart != -1 {
				nameStart := quoteStart + 1 // +1 for the opening quote
				nameEnd := nameStart + len(parsedName)

				packages[key].NameLocation = &models.FilePosition{
					Line:     models.Position{Start: lineNumber, End: lineNumber},
					Column:   models.Position{Start: nameStart, End: nameEnd},
					Filename: sourcefile.Path(),
				}

				// Find the position of the version if it exists
				if versionOperator != "" && version != "" {
					versionStart := nameEnd + len(extras) + len(versionOperator)
					versionEnd := versionStart + len(version)

					packages[key].VersionLocation = &models.FilePosition{
						Line:     models.Position{Start: lineNumber, End: lineNumber},
						Column:   models.Position{Start: versionStart, End: versionEnd},
						Filename: sourcefile.Path(),
					}
				}
			}

			packages[key].IsDirect = true

			return true
		}
	}

	return false
}

// matchPoetryDependency matches dependencies in Poetry/Pipfile format: package = "version"
func matchPoetryDependency(lowerLine, lowerName, originalLine string, lineNumber int, sourcefile lockfile.DepFile, key int, packages []lockfile.PackageDetails, inDevDepTable bool) {
	startColumn := fileposition.GetFirstNonEmptyCharacterIndexInLine(originalLine)
	endColumn := fileposition.GetLastNonEmptyCharacterIndexInLine(originalLine)

	packages[key].BlockLocation = models.FilePosition{
		Line:     models.Position{Start: lineNumber, End: lineNumber},
		Column:   models.Position{Start: startColumn, End: endColumn},
		Filename: sourcefile.Path(),
	}

	nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerName, lineNumber)
	if nameLocation != nil {
		nameLocation.Filename = sourcefile.Path()
		packages[key].NameLocation = nameLocation
	}

	versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, ".*", lineNumber, "=\\s*\"", "\"")
	if versionLocation != nil {
		versionLocation.Filename = sourcefile.Path()
		packages[key].VersionLocation = versionLocation
	}

	packages[key].IsDirect = true

	if inDevDepTable {
		packages[key].DepGroups = append(packages[key].DepGroups, "dev")
	}
}

var _ lockfile.Matcher = PyprojectTOMLMatcher{}
