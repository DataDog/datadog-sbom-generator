package rust

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

func (e CargoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.CratesFilePath.String()
}

func (e CargoLockExtractor) IsOfficiallySupported() bool {
	return cargoOfficiallySupported
}

func (e CargoLockExtractor) PackageManager() models.PackageManager {
	return cargoPackageManager
}

func (e CargoLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *CargoLockFile

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
		packages = append(packages, extractor.PackageDetails{
			Name:           lockPackage.Name,
			Version:        lockPackage.Version,
			PackageManager: cargoPackageManager,
			Ecosystem:      models.EcosystemCratesIO,
		})
	}

	// Set BlockLocation for each package using the InTOML utility
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	positions := make([]*models.FilePosition, len(packages))
	for i := range packages {
		positions[i] = &packages[i].BlockLocation
	}

	fileposition.InTOML("[[package]]", "", positions, lines)

	for i := range packages {
		packages[i].BlockLocation.Filename = f.Path()
		packages[i].LocationRole = models.LocationRoleLockfile
	}

	return packages, nil
}

var cargoExtractor = CargoLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&CargoTomlMatcher{}}},
}

func ParseCargoLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, cargoExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.CratesFilePath, cargoExtractor)
}
