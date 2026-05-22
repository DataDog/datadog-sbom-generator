package dotnet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"maps"
)

func parseNuGetLockDependencies(
	dependencies map[string]NuGetLockPackage,
	positions map[string]*models.FilePosition,
	filePath string,
) map[string]lockfile.PackageDetails {
	details := map[string]lockfile.PackageDetails{}

	for name, dependency := range dependencies {
		if strings.EqualFold(dependency.Type, projectDependencyType) {
			continue
		}
		pkgDetails := lockfile.PackageDetails{
			Name:           name,
			Version:        dependency.Resolved,
			PackageManager: nugetPackageManager,
			Ecosystem:      models.EcosystemNuGet,
			IsDirect:       dependency.Type == "Direct",
		}
		if pos, ok := positions[name]; ok {
			blockLocation := *pos
			blockLocation.Filename = filePath
			pkgDetails.BlockLocation = blockLocation
			pkgDetails.LocationRole = models.LocationRoleLockfile
		}
		details[name+"@"+dependency.Resolved] = pkgDetails
	}

	return details
}

func parseNuGetLock(
	file NuGetLockfile,
	lines []string,
	filePath string,
) ([]lockfile.PackageDetails, error) {
	details := map[string]lockfile.PackageDetails{}

	// go through the dependencies for each framework, e.g. `net6.0` and parse
	// its dependencies, there might be different or duplicate dependencies
	// between frameworks.
	// Sort framework names so that when the same package appears in multiple
	// frameworks, the first framework alphabetically wins (deterministic output).
	frameworkNames := slices.Sorted(maps.Keys(file.Dependencies))
	for _, frameworkName := range frameworkNames {
		dependencies := file.Dependencies[frameworkName]
		// Build position map for this framework's packages
		positions := make(map[string]*models.FilePosition, len(dependencies))
		for name := range dependencies {
			positions[name] = &models.FilePosition{}
		}

		fileposition.InJSON(frameworkName, positions, lines, 0)

		maps.Copy(details, parseNuGetLockDependencies(dependencies, positions, filePath))
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

func (e NuGetLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *NuGetLockfile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = json.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	if parsedLockfile.Version != 1 && parsedLockfile.Version != 2 {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract: unsupported lock file version %d", parsedLockfile.Version)
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	return parseNuGetLock(*parsedLockfile, lines, f.Path())
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
