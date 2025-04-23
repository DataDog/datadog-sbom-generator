package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"golang.org/x/exp/maps"
)

type PipenvPackage struct {
	Version string `json:"version"`
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

const PipenvEcosystem = PipEcosystem

type PipenvLockExtractor struct {
	WithMatcher
}

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "Pipfile.lock"
}

func (e PipenvLockExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *PipenvLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	details := make(map[string]models.PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages, "")
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev")

	return maps.Values(details), nil
}

func addPkgDetails(details map[string]models.PackageDetails, packages map[string]PipenvPackage, group string) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		if _, ok := details[name+"@"+version]; !ok {
			pkgDetails := models.PackageDetails{
				Name:           name,
				Version:        version,
				PackageManager: models.Pipfile,
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
	WithMatcher{Matchers: []Matcher{&PipfileMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("Pipfile.lock", PipenvExtractor)
}

func ParsePipenvLock(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, PipenvExtractor)
}
