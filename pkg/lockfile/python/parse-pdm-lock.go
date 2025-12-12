package python

import (
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

func (p PdmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PdmFilePath.String()
}

func (p PdmLockExtractor) IsOfficiallySupported() bool {
	return pdmOfficiallySupported
}

func (p PdmLockExtractor) PackageManager() models.PackageManager {
	return pdmPackageManager
}

func (p PdmLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockFile *PdmLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockFile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	packages := make([]lockfile.PackageDetails, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		details := lockfile.PackageDetails{
			Name:           pkg.Name,
			Version:        pkg.Version,
			PackageManager: pdmPackageManager,
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

var _ lockfile.Extractor = PdmLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PdmFilePath, PdmLockExtractor{})
}

func ParsePdmLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PdmLockExtractor{})
}
