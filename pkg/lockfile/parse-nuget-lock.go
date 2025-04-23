package lockfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"golang.org/x/exp/maps"
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
	NuGetEcosystem        Ecosystem = "NuGet"
	projectDependencyType string    = "Project"
)

func parseNuGetLockDependencies(dependencies map[string]NuGetLockPackage) map[string]models.PackageDetails {
	details := map[string]models.PackageDetails{}

	for name, dependency := range dependencies {
		if strings.EqualFold(dependency.Type, projectDependencyType) {
			continue
		}
		details[name+"@"+dependency.Resolved] = models.PackageDetails{
			Name:           name,
			Version:        dependency.Resolved,
			PackageManager: models.NuGet,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       dependency.Type == "Direct",
		}
	}

	return details
}

func parseNuGetLock(lockfile NuGetLockfile) ([]models.PackageDetails, error) {
	details := map[string]models.PackageDetails{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks
	for _, dependencies := range lockfile.Dependencies {
		maps.Copy(details, parseNuGetLockDependencies(dependencies))
	}

	return maps.Values(details), nil
}

type NuGetLockExtractor struct {
	WithMatcher
}

func (e NuGetLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == "packages.lock.json"
}

func (e NuGetLockExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *NuGetLockfile

	err := json.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	if parsedLockfile.Version != 1 && parsedLockfile.Version != 2 {
		return []models.PackageDetails{}, fmt.Errorf("could not extract: unsupported lock file version %d", parsedLockfile.Version)
	}

	return parseNuGetLock(*parsedLockfile)
}

var NuGetExtractor = NuGetLockExtractor{
	WithMatcher{Matchers: []Matcher{&NugetCsprojMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("packages.lock.json", NuGetExtractor)
}

func ParseNuGetLock(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, NuGetExtractor)
}
