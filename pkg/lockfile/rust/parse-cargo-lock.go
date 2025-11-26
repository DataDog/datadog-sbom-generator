package rust

import (
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

const (
	cargoPackageManager      = models.Crates
	cargoOfficiallySupported = true
)

type CargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type CargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []CargoLockPackage `toml:"package"`
}

type CargoLockExtractor struct{}

func (e CargoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.CratesFilePath.String()
}

func (e CargoLockExtractor) IsOfficiallySupported() bool {
	return cargoOfficiallySupported
}

func (e CargoLockExtractor) PackageManager() models.PackageManager {
	return cargoPackageManager
}

func (e CargoLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *CargoLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

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

	return packages, nil
}

var _ lockfile.Extractor = CargoLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.CratesFilePath, CargoLockExtractor{})
}

func ParseCargoLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, CargoLockExtractor{})
}
