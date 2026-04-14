package java

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e GradleVerificationMetadataExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) IsOfficiallySupported() bool {
	return gradleVerificationOfficiallySupported
}

func (e GradleVerificationMetadataExtractor) PackageManager() models.PackageManager {
	return gradleVerificationPackageManager
}

// componentKey builds a unique key from a component's attributes for position lookup.
func componentKey(group, name, version string) string {
	return group + ":" + name + ":" + version
}

var componentStartRe = cachedregexp.MustCompile(`<component\s+group="([^"]+)"\s+name="([^"]+)"\s+version="([^"]+)"`)

// extractComponentPositions scans lines for <component> blocks and returns positions keyed by group:name:version.
// When the same group:name:version appears multiple times (multiple versions scenario),
// we store positions in order and consume them sequentially.
func extractComponentPositions(lines []string) map[string][]models.FilePosition {
	positions := make(map[string][]models.FilePosition)

	for i, line := range lines {
		matches := componentStartRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		group, name, version := matches[1], matches[2], matches[3]
		key := componentKey(group, name, version)
		lineNum := i + 1 // 1-indexed

		colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		colEnd := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

		// Find the end of this component block (</component> or self-closing />)
		endLine := lineNum
		if !strings.Contains(line, "/>") {
			for j := i + 1; j < len(lines); j++ {
				if strings.Contains(lines[j], "</component>") {
					endLine = j + 1
					colEnd = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[j])

					break
				}
			}
		}

		positions[key] = append(positions[key], models.FilePosition{
			Line:   models.Position{Start: lineNum, End: endLine},
			Column: models.Position{Start: colStart, End: colEnd},
		})
	}

	return positions
}

func (e GradleVerificationMetadataExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = xml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := fileposition.BytesToLines(content)
	positions := extractComponentPositions(lines)

	// Track consumption index per key for duplicate group:name:version entries
	consumed := make(map[string]int)

	pkgs := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		key := componentKey(component.Group, component.Name, component.Version)

		pkg := lockfile.PackageDetails{
			Name:           component.Group + ":" + component.Name,
			Version:        component.Version,
			PackageManager: gradleVerificationPackageManager,
			Ecosystem:      models.EcosystemMaven,
			LocationRole:   models.LocationRoleLockfile,
		}

		if posList, ok := positions[key]; ok {
			idx := consumed[key]
			if idx < len(posList) {
				pos := posList[idx]
				pos.Filename = f.Path()
				pkg.BlockLocation = pos
				consumed[key] = idx + 1
			}
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

var GradleVerificationExtractor = GradleVerificationMetadataExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&BuildGradleMatcher{}}},
}

func ParseGradleVerificationMetadata(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, GradleVerificationExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.GradleVerificationFilePath, GradleVerificationExtractor)
}
