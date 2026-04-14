package rust

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
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

func (e CargoLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *CargoLockFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	_, err = toml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, lockfile.PackageDetails{
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
	}

	return packages, nil
}

var cargoExtractor = CargoLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&CargoTomlMatcher{}}},
}

func ParseCargoLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, cargoExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.CratesFilePath, cargoExtractor)
}
