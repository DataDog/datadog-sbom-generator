package python

import (
	"cmp"
	"log"
	"maps"
	"math"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type pyprojectPackageCollector struct {
	packages       map[string]extractor.PackageDetails
	lines          []string
	path           string
	packageManager models.PackageManager
}

func (c *pyprojectPackageCollector) addDependency(dependency pep508Dependency, groups []string, isPoetry bool) {
	if (dependency.Version == "") == (dependency.VersionRange == "") {
		log.Printf(
			"Invalid pyproject dependency state for %q from %s: expected exactly one of version or version range, got version=%q versionRange=%q\n",
			dependency.Name,
			c.path,
			dependency.Version,
			dependency.VersionRange,
		)

		return
	}

	block, nameLocation, versionLocation := extractPositions(c.lines, c.path, dependency.RawName, versionOrRange(dependency.Version, dependency.VersionRange), isPoetry)
	c.addOrMergePackageGroups(extractor.PackageDetails{
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
func (c *pyprojectPackageCollector) addOrMergePackageGroups(pkg extractor.PackageDetails) {
	key := pyprojectPackageKey(pkg)
	if existing, exists := c.packages[key]; exists {
		mergeDepGroups(&existing, pkg.DepGroups)
		c.packages[key] = existing

		return
	}
	c.logVersionRangeConflict(pkg)
	c.packages[key] = pkg
}

// pyprojectPackageKey keeps declarations separate unless the package name and
// the exact version or range match, so duplicate declarations can merge groups
// without dropping distinct constraints.
func pyprojectPackageKey(pkg extractor.PackageDetails) string {
	return pkg.Name + "@" + pkg.Version + "|" + pkg.VersionRange
}

func mergeDepGroups(pkg *extractor.PackageDetails, groups []string) {
	for _, group := range groups {
		if !slices.Contains(pkg.DepGroups, group) {
			pkg.DepGroups = append(pkg.DepGroups, group)
		}
	}
}

// logVersionRangeConflict warns when two ranges for the same package will later
// share an unversioned PURL in CycloneDX output. The packages stay separate here
// so their source locations can still be preserved.
func (c *pyprojectPackageCollector) logVersionRangeConflict(pkg extractor.PackageDetails) {
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

func hasConflictingVersionRange(existing, pkg extractor.PackageDetails) bool {
	return existing.Name == pkg.Name &&
		existing.VersionRange != "" &&
		existing.VersionRange != pkg.VersionRange
}

func sortedPyprojectPackages(packages map[string]extractor.PackageDetails) []extractor.PackageDetails {
	result := slices.Collect(maps.Values(packages))
	slices.SortFunc(result, comparePyprojectPackageDetails)

	return result
}

// comparePyprojectPackageDetails sorts by pyproject.toml location first. Entries
// without a parsed location sort last, then package fields break ties.
func comparePyprojectPackageDetails(a, b extractor.PackageDetails) int {
	if c := strings.Compare(a.BlockLocation.Filename, b.BlockLocation.Filename); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceLine(a.BlockLocation), sourceLine(b.BlockLocation)); c != 0 {
		return c
	}
	if c := cmp.Compare(sourceColumn(a.BlockLocation), sourceColumn(b.BlockLocation)); c != 0 {
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

// sourceLine returns a sortable line number. Missing source positions sort last
// so packages with extracted manifest locations preserve source order first.
func sourceLine(location models.FilePosition) int {
	if location.Line.Start == 0 {
		return math.MaxInt
	}

	return location.Line.Start
}

// sourceColumn returns a sortable column number. Missing source positions sort
// last, then name/version/range comparisons below keep ordering deterministic.
func sourceColumn(location models.FilePosition) int {
	if location.Column.Start == 0 {
		return math.MaxInt
	}

	return location.Column.Start
}

// versionOrRange returns the manifest value to anchor when extracting source
// positions; each dependency should have exactly one of these set.
func versionOrRange(version, versionRange string) string {
	if version != "" {
		return version
	}

	return versionRange
}
