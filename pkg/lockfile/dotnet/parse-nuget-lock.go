package dotnet

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"maps"
)

func parseNuGetLockDependencies(dependencies map[string]NuGetLockPackage) map[string]lockfile.PackageDetails {
	details := map[string]lockfile.PackageDetails{}

	for name, dependency := range dependencies {
		if strings.EqualFold(dependency.Type, projectDependencyType) {
			continue
		}
		details[name+"@"+dependency.Resolved] = lockfile.PackageDetails{
			Name:           name,
			Version:        dependency.Resolved,
			PackageManager: nugetPackageManager,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       dependency.Type == "Direct",
		}
	}

	return details
}

func parseNuGetLock(file NuGetLockfile) ([]lockfile.PackageDetails, error) {
	details := map[string]lockfile.PackageDetails{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range file.Dependencies {
		maps.Copy(details, parseNuGetLockDependencies(dependencies))
	}

	return slices.Collect(maps.Values(details)), nil
}

func (e NuGetLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.NugetLockFilePath.String()
}

func (e NuGetLockExtractor) IsOfficiallySupported() bool {
	return nugetOfficiallySupported
}

func (e NuGetLockExtractor) PackageManager() models.PackageManager {
	return nugetPackageManager
}

func (e NuGetLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *NuGetLockfile

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	if parsedLockfile.Version != 1 && parsedLockfile.Version != 2 {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract: unsupported lock file version %d", parsedLockfile.Version)
	}

	return parseNuGetLock(*parsedLockfile)
}

var NuGetExtractor = NuGetLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&NugetCsprojMatcher{}}},
}

func ParseNuGetLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, NuGetExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.NugetLockFilePath, NuGetExtractor)
}
