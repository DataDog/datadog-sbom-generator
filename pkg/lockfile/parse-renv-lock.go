package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type RenvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Repository string `json:"Repository"`
}

type RenvLockfile struct {
	Packages map[string]RenvPackage `json:"Packages"`
}

const CRANEcosystem Ecosystem = "CRAN"

type RenvLockExtractor struct{}

func (e RenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "renv.lock"
}

func (e RenvLockExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *RenvLockfile

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]models.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != string(CRANEcosystem) {
			continue
		}

		packages = append(packages, models.PackageDetails{
			Name:           pkg.Package,
			Version:        pkg.Version,
			PackageManager: models.Renv,
			Ecosystem:      models.EcosystemCRAN,
		})
	}

	return packages, nil
}

var _ Extractor = RenvLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("renv.lock", RenvLockExtractor{})
}

func ParseRenvLock(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, RenvLockExtractor{})
}
