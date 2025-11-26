package php

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	composerPackageManager      = models.Composer
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
	lockfile.WithMatcher
}

func (e ComposerLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.ComposerFilePath.String()
}

func (e ComposerLockExtractor) IsOfficiallySupported() bool {
	return composerOfficiallySupported
}

func (e ComposerLockExtractor) PackageManager() models.PackageManager {
	return composerPackageManager
}

func (e ComposerLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *ComposerLock

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make(
		[]lockfile.PackageDetails,
		0,
		// len cannot return negative numbers, but the types can't reflect that
		uint64(len(parsedLockfile.Packages))+uint64(len(parsedLockfile.PackagesDev)),
	)

	for _, composerPackage := range parsedLockfile.Packages {
		packages = append(packages, lockfile.PackageDetails{
			Name:           composerPackage.Name,
			Version:        composerPackage.Version,
			Commit:         composerPackage.Dist.Reference,
			PackageManager: composerPackageManager,
			Ecosystem:      models.EcosystemPackagist,
		})
	}

	for _, composerPackage := range parsedLockfile.PackagesDev {
		packages = append(packages, lockfile.PackageDetails{
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
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&ComposerMatcher{}}},
}

func ParseComposerLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, ComposerExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.ComposerFilePath, ComposerExtractor)
}
