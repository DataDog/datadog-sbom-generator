package php

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	composerPackageManager      = models.Composer
	composerOfficiallySupported = true
)

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	PackagesDev []ComposerPackage `json:"packages-dev"`
}

type ComposerLockExtractor struct {
	extractor.WithMatcher
}

func (e ComposerLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.ComposerFilePath.String()
}

func (e ComposerLockExtractor) IsOfficiallySupported() bool {
	return composerOfficiallySupported
}

func (e ComposerLockExtractor) PackageManager() models.PackageManager {
	return composerPackageManager
}

// computeComposerBlockPositions scans JSON lines to find the start/end
// positions of each object in the "packages" and "packages-dev" arrays.
// Returns positions in order: packages first, then packages-dev.
func computeComposerBlockPositions(lines []string) []models.FilePosition {
	var positions []models.FilePosition

	packagesKeyRe := cachedregexp.MustCompile(`^\s*"packages(-dev)?"\s*:\s*\[`)
	inArray := false
	braceDepth := 0
	var currentStart int

	for i, line := range lines {
		lineNum := i + 1 // 1-indexed

		if !inArray {
			if packagesKeyRe.MatchString(line) {
				inArray = true
				braceDepth = 0
			}

			continue
		}

		// Count braces on this line
		for _, ch := range line {
			switch ch {
			case '{':
				braceDepth++
				if braceDepth == 1 {
					currentStart = lineNum
				}
			case '}':
				if braceDepth == 1 {
					positions = append(positions, models.FilePosition{
						Line:   models.Position{Start: currentStart, End: lineNum},
						Column: models.Position{Start: strings.IndexByte(lines[currentStart-1], '{') + 1, End: strings.IndexByte(line, '}') + 2},
					})
				}
				braceDepth--
			}
		}

		// Check if array is closed (line has ']' at depth 0)
		if braceDepth == 0 && strings.Contains(line, "]") {
			inArray = false
		}
	}

	return positions
}

func (e ComposerLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *ComposerLock

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	err = json.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// Compute block positions for all packages in both arrays
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	blockPositions := computeComposerBlockPositions(lines)

	packages := make(
		[]extractor.PackageDetails,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	posIdx := 0
	for _, composerPackage := range parsedLockfile.Packages {
		pkg := extractor.PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: composerPackageManager,
			Ecosystem:      models.EcosystemPackagist,
		}
		if posIdx < len(blockPositions) {
			pkg.BlockLocation = blockPositions[posIdx]
			pkg.BlockLocation.Filename = f.Path()
			pkg.LocationRole = models.LocationRoleLockfile
			posIdx++
		}
		packages = append(packages, pkg)
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		pkg := extractor.PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: composerPackageManager,
			Ecosystem:      models.EcosystemPackagist,
			DepGroups:      []string{"dev"},
		}
		if posIdx < len(blockPositions) {
			pkg.BlockLocation = blockPositions[posIdx]
			pkg.BlockLocation.Filename = f.Path()
			pkg.LocationRole = models.LocationRoleLockfile
			posIdx++
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetArtifact implements extractor.ArtifactExtractor.
// It reads the co-located composer.json to extract the project name.
func (e ComposerLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:  f.Path(),
			Ecosystem: models.EcosystemPackagist,
		},
	}

	lockfileDir := filepath.Dir(f.Path())
	composerJSONPath := filepath.Join(lockfileDir, composerFilename)

	data, err := os.ReadFile(composerJSONPath)
	if err != nil {
		// composer.json missing or unreadable — return artifact with empty name
		return artifact, nil
	}

	var parsed struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return artifact, nil
	}

	artifact.Name = parsed.Name

	return artifact, nil
}

var _ extractor.ArtifactExtractor = ComposerLockExtractor{}

var ComposerExtractor = ComposerLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&ComposerMatcher{}}},
}

func ParseComposerLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, ComposerExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.ComposerFilePath, ComposerExtractor)
}
