package javascript

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"maps"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

func getCleanedVersion(sourceFile PnpmLockfile, name, version string) string {
	if strings.HasPrefix(version, "https://codeload.github.com") {
		// This is a link to a tarball, not a version we need to check the resolved version in the package section
		if pkg, ok := sourceFile.Packages[name+"@"+version]; ok {
			return pkg.Version
		}

		return ""
	}

	return strings.Split(version, "(")[0]
}

func getCommitFromVersion(version string) string {
	if strings.HasPrefix(version, "https://codeload.github.com") {
		re := cachedregexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
		matched := re.FindStringSubmatch(version)

		if matched != nil {
			return matched[1]
		}
	}

	return ""
}

func mergeSlices(fromSlices ...[]string) []string {
	result := make(map[string]bool)
	for _, slice := range fromSlices {
		for _, item := range slice {
			result[item] = true
		}
	}

	return slices.Collect(maps.Keys(result))
}

func addDependencyToPackageDetails(dependency lockfile.PackageDetails, packageIdentifier string, deps map[string]lockfile.PackageDetails) map[string]lockfile.PackageDetails {
	if dep, exists := deps[packageIdentifier]; exists {
		newDepGroups := mergeSlices(dep.DepGroups, dependency.DepGroups)
		newTargetedVersions := mergeSlices(dep.TargetVersions, dependency.TargetVersions)

		if len(newDepGroups) > 0 {
			dep.DepGroups = newDepGroups
		}
		if len(newTargetedVersions) > 0 {
			dep.TargetVersions = newTargetedVersions
		}
		dep.IsDirect = dep.IsDirect || dependency.IsDirect
		deps[packageIdentifier] = dep
	} else {
		deps[packageIdentifier] = dependency
	}

	return deps
}

func extractTransitiveDeps(sourceFile PnpmLockfile, root PnpmDirectDependency, targetedKey string, deps map[string]lockfile.PackageDetails) map[string]lockfile.PackageDetails {
	// Need to look at dependencies
	visitedSnapshots := make(map[string]bool)
	snapshotQueue := make([]string, 0)
	snapshotQueue = append(snapshotQueue, targetedKey)

	for len(snapshotQueue) > 0 {
		targetedKey = snapshotQueue[0]
		snapshotQueue = snapshotQueue[1:]

		if _, visited := visitedSnapshots[targetedKey]; visited {
			continue
		}

		visitedSnapshots[targetedKey] = true
		snapshot, ok := sourceFile.Snapshots[targetedKey]

		if !ok {
			continue
		}

		for depName, depVersion := range snapshot.Dependencies {
			transitiveDep := lockfile.PackageDetails{
				Name:           depName,
				Version:        getCleanedVersion(sourceFile, depName, depVersion),
				Commit:         getCommitFromVersion(depVersion),
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      root.Pkg.DepGroups,
				PackageManager: models.Pnpm,
				IsDirect:       false,
			}
			addDependencyToPackageDetails(transitiveDep, getPnpmDependencyKey(transitiveDep), deps)
			childKey := depName + "@" + depVersion
			snapshotQueue = append(snapshotQueue, childKey)
		}

		for depName, depVersion := range snapshot.OptionalDependencies {
			transitiveDep := lockfile.PackageDetails{
				Name:           depName,
				Version:        getCleanedVersion(sourceFile, depName, depVersion),
				Commit:         getCommitFromVersion(depVersion),
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      root.Pkg.DepGroups,
				PackageManager: models.Pnpm,
				IsDirect:       false,
			}
			addDependencyToPackageDetails(transitiveDep, getPnpmDependencyKey(transitiveDep), deps)
			childKey := depName + "@" + depVersion
			snapshotQueue = append(snapshotQueue, childKey)
		}
	}

	return deps
}

func extractDirectDependencies(sourceFile PnpmLockfile, roots []PnpmDirectDependency, dependencies PnpmDependencies, depGroup string, workspacePath string) []PnpmDirectDependency {
	for dependencyName, dependency := range dependencies {
		var nameLocation *models.FilePosition
		if workspacePath != "" && workspacePath != "." {
			nameLocation = &models.FilePosition{Filename: workspacePath}
		}

		roots = append(roots, PnpmDirectDependency{
			Pkg: lockfile.PackageDetails{
				Name:           dependencyName,
				Version:        getCleanedVersion(sourceFile, dependencyName, dependency.Version),
				Commit:         getCommitFromVersion(dependency.Version),
				TargetVersions: []string{dependency.Specifier},
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      []string{depGroup},
				PackageManager: models.Pnpm,
				IsDirect:       true,
				NameLocation:   nameLocation,
			},
			Dep:           dependency,
			WorkspacePath: workspacePath,
		})
	}

	return roots
}

func parsePnpmLock(sourceFile PnpmLockfile) []lockfile.PackageDetails {
	// First create the deps tree
	// To do so, first look at the packages list, for each package, look into the importers
	// If present in the importers => its direct and we know its scope
	// Then looking at snapshot, we can build its branch

	// Going through the importers to get a direct (prod or dev), then finding the transitives in the snapshot
	directDependencies := make([]PnpmDirectDependency, 0)
	for workspacePath, importer := range sourceFile.Importers {
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.Dependencies, "prod", workspacePath)
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.OptionalDependencies, "optional", workspacePath)
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.DevDependencies, "dev", workspacePath)
	}

	packages := make(map[string]lockfile.PackageDetails)
	for _, direct := range directDependencies {
		packages = addDependencyToPackageDetails(direct.Pkg, getPnpmWorkspaceDependencyKey(direct), packages)
		packages = extractTransitiveDeps(sourceFile, direct, direct.Pkg.Name+"@"+direct.Dep.Version, packages)
	}

	return slices.Collect(maps.Values(packages))
}

func getPnpmWorkspaceDependencyKey(direct PnpmDirectDependency) string {
	return getWorkspaceDependencyKey(direct.Pkg.Name, direct.Pkg.Version, direct.WorkspacePath)
}

func getPnpmDependencyKey(pkg lockfile.PackageDetails) string {
	return getWorkspaceDependencyKey(pkg.Name, pkg.Version, "") // this has no workspace path
}

func (e PnpmLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PnpmLockfile

	err := yaml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// this will happen if the file is empty
	if parsedLockfile == nil {
		parsedLockfile = &PnpmLockfile{}
	}

	// Check if we need to use the legacy extractor instead
	lockfileVersion, _ := strconv.ParseFloat(strings.ReplaceAll(parsedLockfile.Version, "-flavoured", ""), 32)
	if lockfileVersion < 7.0 {
		file, err := f.Open(f.Path())
		if err != nil {
			return []lockfile.PackageDetails{}, err
		}
		defer file.Close()

		return e.extractLegacyPnpm(file)
	}

	return parsePnpmLock(*parsedLockfile), nil
}

var PnpmExtractor = PnpmLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageJSONMatcher{}}},
}

func ParsePnpmLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PnpmExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PnpmFilePath, PnpmExtractor)
}
