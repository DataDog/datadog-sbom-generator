package python

import (
	"cmp"
	"log"
	"maps"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type pyprojectPackageCollector struct {
	packages       map[string]lockfile.PackageDetails
	lines          []string
	path           string
	packageManager models.PackageManager
}

func (c *pyprojectPackageCollector) addDependency(dependency pep508Dependency, groups []string, isPoetry bool) {
	if (dependency.Version == "") == (dependency.VersionRange == "") {
		log.Printf(
			"Skipping pyproject dependency %q from %s: expected exactly one of version or version range, got version=%q versionRange=%q\n",
			dependency.Name,
			c.path,
			dependency.Version,
			dependency.VersionRange,
		)

		return
	}

	block, nameLocation, versionLocation := extractPositions(c.lines, c.path, dependency.RawName, dependency.RawValue, versionOrRange(dependency.Version, dependency.VersionRange), isPoetry)
	c.addOrMergePackageGroups(lockfile.PackageDetails{
		Name:                         dependency.Name,
		Version:                      dependency.Version,
		VersionRange:                 dependency.VersionRange,
		PackageManager:               c.packageManager,
		Ecosystem:                    models.EcosystemPyPI,
		IsDirect:                     true,
		RequiresTransitiveEnrichment: true,
		DepGroups:                    groups,
		BlockLocation:                block,
		NameLocation:                 nameLocation,
		VersionLocation:              versionLocation,
		LocationRole:                 models.LocationRoleManifest,
	})
}

// addOrMergePackageGroups adds a package to the map, or if it already exists (same name+version/range),
// merges the new dep groups into the existing entry rather than dropping the duplicate.
func (c *pyprojectPackageCollector) addOrMergePackageGroups(pkg lockfile.PackageDetails) {
	key := pyprojectPackageKey(pkg)
	if existing, exists := c.packages[key]; exists {
		mergeDepGroups(&existing, pkg.DepGroups)
		c.packages[key] = existing

		return
	}
	c.logVersionRangeConflict(pkg)
	c.packages[key] = pkg
}

func pyprojectPackageKey(pkg lockfile.PackageDetails) string {
	return pkg.Name + "@" + pkg.Version + "|" + pkg.VersionRange
}

func mergeDepGroups(pkg *lockfile.PackageDetails, groups []string) {
	for _, group := range groups {
		if !slices.Contains(pkg.DepGroups, group) {
			pkg.DepGroups = append(pkg.DepGroups, group)
		}
	}
}

func (c *pyprojectPackageCollector) logVersionRangeConflict(pkg lockfile.PackageDetails) {
	if pkg.VersionRange == "" {
		return
	}

	for _, existing := range c.packages {
		if !hasConflictingVersionRange(existing, pkg) {
			continue
		}

		log.Printf(
			"Multiple pyproject version ranges for dependency %q from %s collapse to the same unversioned PURL; CycloneDX output will keep the earliest source declaration. Saw ranges %q and %q\n",
			pkg.Name,
			c.path,
			existing.VersionRange,
			pkg.VersionRange,
		)

		return
	}
}

func hasConflictingVersionRange(existing, pkg lockfile.PackageDetails) bool {
	return existing.Name == pkg.Name &&
		existing.VersionRange != "" &&
		existing.VersionRange != pkg.VersionRange
}

func sortedPyprojectPackages(packages map[string]lockfile.PackageDetails) []lockfile.PackageDetails {
	result := slices.Collect(maps.Values(packages))
	slices.SortFunc(result, comparePyprojectPackageDetails)

	return result
}

func comparePyprojectPackageDetails(a, b lockfile.PackageDetails) int {
	if c := strings.Compare(a.BlockLocation.Filename, b.BlockLocation.Filename); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceLine(a.BlockLocation), sourceLine(b.BlockLocation)); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceColumn(a.BlockLocation), sourceColumn(b.BlockLocation)); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceLinePtr(a.NameLocation), sourceLinePtr(b.NameLocation)); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceColumnPtr(a.NameLocation), sourceColumnPtr(b.NameLocation)); c != 0 {
		return c
	}
	if c := strings.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := strings.Compare(a.Version, b.Version); c != 0 {
		return c
	}

	return strings.Compare(a.VersionRange, b.VersionRange)
}

func sourceLine(location models.FilePosition) int {
	if location.Line.Start == 0 {
		return 1 << 30
	}

	return location.Line.Start
}

func sourceColumn(location models.FilePosition) int {
	if location.Column.Start == 0 {
		return 1 << 30
	}

	return location.Column.Start
}

func sourceLinePtr(location *models.FilePosition) int {
	if location == nil {
		return 1 << 30
	}

	return sourceLine(*location)
}

func sourceColumnPtr(location *models.FilePosition) int {
	if location == nil {
		return 1 << 30
	}

	return sourceColumn(*location)
}

func versionOrRange(version, versionRange string) string {
	if version != "" {
		return version
	}

	return versionRange
}
