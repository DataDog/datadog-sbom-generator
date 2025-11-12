package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	composerPackageManager      = models.Composer
	composerFilePath            = models.ComposerFilePath
	composerOfficiallySupported = true
)

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Reference string `json:"reference"`
	} `json:"dist"`
}

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	PackagesDev []ComposerPackage `json:"packages-dev"`
}

type ComposerLockExtractor struct {
	WithMatcher
}

func (e ComposerLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == composerFilePath
}

func (e ComposerLockExtractor) IsOfficiallySupported() bool {
	return composerOfficiallySupported
}

func (e ComposerLockExtractor) PackageManager() models.PackageManager {
	return composerPackageManager
}

func (e ComposerLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *ComposerLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make(
		[]PackageDetails,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, composerPackage := range parsedLockfile.Packages {
		packages = append(packages, PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: composerPackageManager,
			Ecosystem:      models.EcosystemPackagist,
		})
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: composerPackageManager,
			Ecosystem:      models.EcosystemPackagist,
			DepGroups:      []string{"dev"},
		})
	}

	return packages, nil
}

var ComposerExtractor = ComposerLockExtractor{
	WithMatcher{Matchers: []Matcher{&ComposerMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor(models.ComposerLock, ComposerExtractor)
}

func ParseComposerLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, ComposerExtractor)
}
