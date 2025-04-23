package lockfile

import (
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

type CargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type CargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []CargoLockPackage `toml:"package"`
}

const CargoEcosystem Ecosystem = "crates.io"

type CargoLockExtractor struct{}

func (e CargoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Cargo.lock"
}

func (e CargoLockExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *CargoLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]models.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		packages = append(packages, models.PackageDetails{
			Name:           lockPackage.Name,
			Version:        lockPackage.Version,
			PackageManager: models.Crates,
			Ecosystem:      models.EcosystemCratesIO,
		})
	}

	return packages, nil
}

var _ Extractor = CargoLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("Cargo.lock", CargoLockExtractor{})
}

func ParseCargoLock(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, CargoLockExtractor{})
}
