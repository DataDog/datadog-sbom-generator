package python

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

func (e PoetryLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PoetryFilePath.String()
}

func (e PoetryLockExtractor) IsOfficiallySupported() bool {
	return poetryOfficiallySupported
}

func (e PoetryLockExtractor) PackageManager() models.PackageManager {
	return poetryPackageManager
}

func (e PoetryLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *PoetryLockFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	_, err = toml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]extractor.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := extractor.PackageDetails{
			Name:           lockPackage.Name,
			Version:        lockPackage.Version,
			Commit:         lockPackage.Source.Commit,
			PackageManager: poetryPackageManager,
			Ecosystem:      models.EcosystemPyPI,
		}
		if lockPackage.Optional {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, "optional")
		}
		packages = append(packages, pkgDetails)
	}

	// Set BlockLocation for each package using the InTOML utility
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	positions := make([]*models.FilePosition, len(packages))
	for i := range packages {
		positions[i] = &packages[i].BlockLocation
	}

	fileposition.InTOML("[[package]]", "[metadata]", positions, lines)

	for i := range packages {
		packages[i].BlockLocation.Filename = f.Path()
		packages[i].LocationRole = models.LocationRoleLockfile
	}

	return packages, nil
}

var PoetryExtractor = PoetryLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&PyprojectTOMLMatcher{}}},
}

func ParsePoetryLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, PoetryExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.PoetryFilePath, PoetryExtractor)
}
