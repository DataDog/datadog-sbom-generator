package renv

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	renvPackageManager      = models.Renv
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
	return filepath.Base(path) == models.RenvFilePath.String()
}

func (e RenvLockExtractor) IsOfficiallySupported() bool {
	return renvOfficiallySupported
}

func (e RenvLockExtractor) PackageManager() models.PackageManager {
	return renvPackageManager
}

func (e RenvLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *RenvLockfile

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != string(models.EcosystemCRAN) {
			continue
		}

		packages = append(packages, lockfile.PackageDetails{
			Name:           pkg.Package,
			Version:        pkg.Version,
			PackageManager: renvPackageManager,
			Ecosystem:      models.EcosystemCRAN,
		})
	}

	return packages, nil
}

var _ lockfile.Extractor = RenvLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.RenvFilePath, RenvLockExtractor{})
}

func ParseRenvLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, RenvLockExtractor{})
}
