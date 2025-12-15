package python

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"maps"
)

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PipfileFilePath.String()
}

func (e PipenvLockExtractor) IsOfficiallySupported() bool {
	return pipenvOfficiallySupported
}

func (e PipenvLockExtractor) PackageManager() models.PackageManager {
	return pipenvPackageManager
}

func (e PipenvLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PipenvLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	details := make(map[string]lockfile.PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages, "")
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev")

	return slices.Collect(maps.Values(details)), nil
}

func addPkgDetails(details map[string]lockfile.PackageDetails, packages map[string]PipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		if _, ok := details[name+"@"+version]; !ok {
			pkgDetails := lockfile.PackageDetails{
				Name:           name,
				Version:        version,
				PackageManager: pipenvPackageManager,
				Ecosystem:      models.EcosystemPyPI,
			}
			if group != "" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, group)
			}
			details[name+"@"+version] = pkgDetails
		}
	}
}

var PipenvExtractor = PipenvLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PipfileMatcher{}}},
}

func ParsePipenvLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PipenvExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PipfileFilePath, PipenvExtractor)
}
