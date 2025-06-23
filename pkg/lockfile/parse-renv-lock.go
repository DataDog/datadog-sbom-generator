package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	renvPackageManager      = models.Renv
	renvFilePath            = "renv.lock"
	renvOfficiallySupported = false
)

type RenvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Repository string `json:"Repository"`
}

type RenvLockfile struct {
	Packages map[string]RenvPackage `json:"Packages"`
}

type RenvLockExtractor struct{}

func (e RenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == renvFilePath
}

func (e RenvLockExtractor) IsOfficiallySupported() bool {
	return renvOfficiallySupported
}

func (e RenvLockExtractor) PackageManager() models.PackageManager {
	return renvPackageManager
}

func (e RenvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *RenvLockfile

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))

	for _, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != string(models.EcosystemCRAN) {
			continue
		}

		packages = append(packages, PackageDetails{
			Name:           pkg.Package,
			Version:        pkg.Version,
			PackageManager: renvPackageManager,
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

func ParseRenvLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, RenvLockExtractor{})
}
