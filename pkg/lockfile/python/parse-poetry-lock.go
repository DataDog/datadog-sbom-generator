package python

import (
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

const (
	poetryPackageManager      = models.Poetry
	poetryOfficiallySupported = true
)

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   PoetryLockPackageSource `toml:"source"`
}

type PoetryLockFile struct {
	Version  int                  `toml:"version"`
	Packages []*PoetryLockPackage `toml:"package"`
}

type PoetryLockExtractor struct {
	lockfile.WithMatcher
}

func (e PoetryLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PoetryFilePath.String()
}

func (e PoetryLockExtractor) IsOfficiallySupported() bool {
	return poetryOfficiallySupported
}

func (e PoetryLockExtractor) PackageManager() models.PackageManager {
	return poetryPackageManager
}

func (e PoetryLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PoetryLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := lockfile.PackageDetails{
			Name:           lockPackage.Name,
			Version:        lockPackage.Version,
			Commit:         lockPackage.Source.Commit,
			PackageManager: poetryPackageManager,
			Ecosystem:      models.EcosystemPyPI,
		}
		if lockPackage.Optional {
			pkgDetails.DepGroups = append(pkgDetails.DepGroups, "optional")
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var PoetryExtractor = PoetryLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PyprojectTOMLMatcher{}}},
}

func ParsePoetryLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PoetryExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PoetryFilePath, PoetryExtractor)
}
