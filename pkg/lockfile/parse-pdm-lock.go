package lockfile

import (
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

type PdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type PdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []PdmLockPackage `toml:"package"`
}

type PdmLockExtractor struct{}

func (p PdmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "pdm.lock"
}

func (p PdmLockExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockFile *PdmLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockFile)
	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	packages := make([]models.PackageDetails, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		details := models.PackageDetails{
			Name:           pkg.Name,
			Version:        pkg.Version,
			PackageManager: models.Pdm,
			Ecosystem:      models.EcosystemPyPI,
		}

		var optional = true
		for _, gr := range pkg.Groups {
			if gr == "dev" {
				details.DepGroups = append(details.DepGroups, "dev")
				optional = false
			} else if gr == "default" {
				optional = false
			}
		}
		if optional {
			details.DepGroups = append(details.DepGroups, "optional")
		}

		if pkg.Revision != "" {
			details.Commit = pkg.Revision
		}

		packages = append(packages, details)
	}

	return packages, nil
}

var _ Extractor = PdmLockExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor("pdm.lock", PdmLockExtractor{})
}

func ParsePdmLock(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, PdmLockExtractor{})
}
