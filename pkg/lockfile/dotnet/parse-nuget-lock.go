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

const (
	nugetPackageManager      = models.NuGet
	nugetOfficiallySupported = true
)

type NuGetLockPackage struct {
	Resolved string `json:"resolved"`
	Type     string `json:"type"`
}

// NuGetLockfile contains the required dependency information as defined in
// https://github.com/NuGet/NuGet.Client/blob/6.5.0.136/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs
type NuGetLockfile struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]NuGetLockPackage `json:"dependencies"`
}

const (
	projectDependencyType string = "Project"
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

type NuGetLockExtractor struct {
	lockfile.WithMatcher
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
