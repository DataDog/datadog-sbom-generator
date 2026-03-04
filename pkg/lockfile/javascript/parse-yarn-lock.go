package javascript

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func shouldSkipYarnLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// Example of block:
//
// "semver@npm:^7.3.3, semver@npm:^7.3.4":
//
//	version: 7.7.3
//	dependencies:
//	 semver: "foobar:^6.0.0"
//
// Where several targetVersions of 'semver' resolve to the same version: "7.7.3"
// In this case, we return 2 YarnPackage. One per TargetVersions.
func parseYarnPackageBlock(block []string) []YarnPackage {
	name, targetVersions, workspacePath := extractYarnPackageNameAndTargetVersions(block[0]) // look at the first line

	packages := make([]YarnPackage, 0, len(targetVersions))
	version := determineYarnPackageVersion(block)
	resolution := determineYarnPackageResolution(block)
	dependencies := determineYarnPackageDependencies(block)

	// Create one YarnPackage per target version
	for _, targetVersion := range targetVersions {
		packages = append(packages, YarnPackage{
			Name:          name,
			Version:       version,
			TargetVersion: targetVersion,
			Resolution:    resolution,
			Dependencies:  dependencies,
			WorkspacePath: workspacePath,
		})
	}

	return packages
}

func groupYarnPackageLines(scanner *bufio.Scanner) []YarnPackage {
	var groups []YarnPackage
	var group []string

	var line string
	for scanner.Scan() {
		line = scanner.Text()

		if shouldSkipYarnLine(line) {
			continue
		}

		// represents the lineStart of a new dependency
		if !strings.HasPrefix(line, " ") {
			if len(group) > 0 {
				packages := parseYarnPackageBlock(group)
				groups = append(groups, packages...)
			}
			group = make([]string, 0)
		}

		group = append(group, line)
	}

	if len(group) > 0 {
		packages := parseYarnPackageBlock(group)
		groups = append(groups, packages...)
	}

	return groups
}

func extractYarnPackageNameAndTargetVersions(line string) (string, []string, string) {
	line = strings.ReplaceAll(line, "\"", "")
	line = strings.TrimSuffix(line, ":")
	parts := strings.Split(line, ",")

	var name, right string
	targetVersions := make([]string, 0)

	for _, part := range parts {
		part = strings.TrimPrefix(part, " ")
		partIsScoped := strings.HasPrefix(part, "@")
		if partIsScoped {
			part = strings.TrimPrefix(part, "@")
		}

		_name, _right, _ := strings.Cut(part, "@")
		if len(name) == 0 {
			name = _name
			if partIsScoped {
				name = "@" + name
			}
		}
		right = _right

		if strings.HasPrefix(right, "npm:") {
			right = strings.TrimPrefix(right, "npm:")
			if strings.Contains(right, "@") {
				resolvedName, resolvedTargetVersions, _ := extractYarnPackageNameAndTargetVersions(right)
				name = resolvedName
				targetVersions = append(targetVersions, resolvedTargetVersions...)

				continue
			}
		}

		// for yarn v2 - it could include these prefixes even when they are not included in package.json
		prefixes := []string{"file", "link", "portal"}
		for _, prefix := range prefixes {
			if strings.HasPrefix(right, prefix+":") {
				right = strings.TrimPrefix(right, prefix+":")
			}
		}

		// for yarn v2 - "file:path/to/dir::locator=...%40workspace%3A.": -> file:path/to/dir
		right, _, _ = strings.Cut(right, "::locator")

		targetVersions = append(targetVersions, right)
	}

	// Extract workspace path if present
	workspacePath := ""
	for _, version := range targetVersions {
		if strings.HasPrefix(version, yarnWorkspaceVersionMarker) {
			workspacePath = strings.TrimPrefix(version, yarnWorkspaceVersionMarker)
			break
		}
	}

	return name, targetVersions, workspacePath
}

func determineYarnPackageVersion(group []string) string {
	// Updated regex to handle empty versions (changed + to * for zero or more characters)
	re := cachedregexp.MustCompile(`^ {2}"?version"?:? "?([\w-.+]*)"?$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			version := matched[1]
			// If version is empty, try to extract from resolution (for git-based packages)
			if version == "" {
				resolution := determineYarnPackageResolution(group)
				if resolution != "" {
					commit := tryExtractCommit(resolution)
					if commit != "" {
						// Use the commit hash as the version for git-based packages
						return commit
					}
				}
			}
			
			return version
		}
	}

	// Version field not found in the package block
	return ""
}

/*
You can find the line parsing regex in action here: https://regex101.com/r/QoJ3b7/3
All expected formats are defined in the regex documentation
*/
func determineYarnPackageDependencies(group []string) []YarnDependency {
	indentCount := -1
	results := make([]YarnDependency, 0)
	lineParsing := cachedregexp.MustCompile(`^"?(?P<package_name>[^\s":]+)"?\s*:?\s*"?(?P<targeted_version>[^"\n]+)"?$`)

	for _, line := range group {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "dependencies") || strings.HasPrefix(trimmed, "optionalDependencies") {
			// start of the dependencies or optionalDependencies section
			indentCount = len(line) - len(trimmed)
		} else if indentCount != -1 && len(line)-len(trimmed) == indentCount {
			// end of the current dependencies section, reset to look for next section
			indentCount = -1
		} else if indentCount != -1 {
			// A line inside the dependencies section, lets parse it
			match := lineParsing.FindStringSubmatch(trimmed)
			if len(match) < 3 {
				// The line have an invalid format, lets skip it
				continue
			}
			name := match[1]
			registry, version, found := strings.Cut(match[2], ":")

			if !found {
				registry = "npm"
				version = match[2]
			}

			results = append(results, YarnDependency{
				Name:     name,
				Version:  version,
				Registry: registry,
			})
		}
	}

	return results
}

func determineYarnPackageResolution(group []string) string {
	re := cachedregexp.MustCompile(`^ {2}"?(?:resolution:|resolved)"? "([^ '"]+)"$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			return matched[1]
		}
	}

	// todo: decide what to do here - maybe panic...?
	return ""
}

func tryExtractCommit(resolution string) string {
	// language=GoRegExp
	matchers := []string{
		// ssh://...
		// git://...
		// git+ssh://...
		// git+https://...
		`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`,
		// https://....git/...
		`(?:^|.+@)https://.+\.git#(\w+)$`,
		`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`,
		`.+#commit[:=](\w+)$`,
		// github:...
		// gitlab:...
		// bitbucket:...
		`^(?:github|gitlab|bitbucket):.+#(\w+)$`,
	}

	for _, matcher := range matchers {
		re := cachedregexp.MustCompile(matcher)
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)

	if err == nil {
		gitRepoHosts := []string{
			"bitbucket.org",
			"github.com",
			"gitlab.com",
		}

		for _, host := range gitRepoHosts {
			if u.Host != host {
				continue
			}

			if u.RawQuery != "" {
				queries := u.Query()

				if queries.Has("ref") {
					return queries.Get("ref")
				}
			}

			return u.Fragment
		}
	}

	return ""
}

/*
buildDependencyTree leverage yarn lockfile format to build the subtree of a package

`rootPkgName` is the name of the package which needs its dependency tree to be built
`rootPkgTargetVersion` is the constraint of the package we search (for example ^1.0.0)
`rootPkgRegistry` is the registry used to download this dependency (defaults to npm)
`dependencies` is the representation of the yarn lockfile, where the key is either package name, registry and target version
or package name and target version and the value is the package definition in Yarn format
`packagesIndex` is an index of all package in datadog-sbom-generator format where the key is the package name and the package version

This methods build the dependency tree by looking at the yarn dependencies definition and matching every transitive dependency
with the index to get a pointer to the datadog-sbom-generator formatted child package
*/
func buildDependencyTree(rootPkgName, rootPkgTargetVersion, rootPkgRegistry string, dependencies map[string]YarnPackage, packagesIndex map[string]*lockfile.PackageDetails) []*lockfile.PackageDetails {
	results := make([]*lockfile.PackageDetails, 0)
	pkg, ok := dependencies[rootPkgName+"@"+rootPkgTargetVersion]
	if !ok {
		pkg, ok = dependencies[rootPkgName+"@"+rootPkgRegistry+":"+rootPkgTargetVersion]
		if !ok {
			return []*lockfile.PackageDetails{}
		}
	}

	for _, dependency := range pkg.Dependencies {
		dependentPackage, ok := dependencies[dependency.Name+"@"+dependency.Version]
		if !ok {
			dependentPackage, ok = dependencies[dependency.Name+"@"+dependency.Registry+":"+dependency.Version]
			if !ok {
				continue
			}
		}
		dep, exists := packagesIndex[dependentPackage.Name+"@"+dependentPackage.TargetVersion]
		if exists {
			results = append(results, dep)
		}
	}

	return results
}

func parseYarnPackage(dependency YarnPackage) lockfile.PackageDetails {
	if dependency.Version == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"Failed to determine version of %s while parsing a yarn.lock - please report this!\n",
			dependency.Name,
		)
	}

	var nameLocation *models.FilePosition
	if dependency.WorkspacePath != "" {
		nameLocation = &models.FilePosition{Filename: dependency.WorkspacePath}
	}

	return lockfile.PackageDetails{
		Name:           dependency.Name,
		Version:        dependency.Version,
		TargetVersions: []string{dependency.TargetVersion},
		PackageManager: yarnPackageManager,
		Ecosystem:      models.EcosystemNPM,
		Commit:         tryExtractCommit(dependency.Resolution),
		NameLocation:   nameLocation,
	}
}

func indexByTargetVersion(packages []YarnPackage) map[string]YarnPackage {
	index := make(map[string]YarnPackage)

	for _, pkg := range packages {
		index[pkg.Name+"@"+pkg.TargetVersion] = pkg
	}

	return index
}

func indexByNameAndVersions(packages []lockfile.PackageDetails) map[string]*lockfile.PackageDetails {
	result := make(map[string]*lockfile.PackageDetails)
	for index, pkg := range packages {
		// packages would have been created with a single TargetVersions
		result[pkg.Name+"@"+pkg.TargetVersions[0]] = &packages[index]
	}

	return result
}

func (e YarnLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.YarnFilePath.String()
}

func (e YarnLockExtractor) IsOfficiallySupported() bool {
	return yarnOfficiallySupported
}

func (e YarnLockExtractor) PackageManager() models.PackageManager {
	return yarnPackageManager
}

func (e YarnLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	scanner := bufio.NewScanner(f)

	yarnPackages := groupYarnPackageLines(scanner)
	yarnPackageIndex := indexByTargetVersion(yarnPackages)

	// Use this index to build all subtrees (trees from each package)
	// Then use all this in the matcher to know is-dev / is-direct and propagate it everywhere

	if err := scanner.Err(); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	// Separate workspace packages from root packages
	workspaces := make([]YarnPackage, 0)
	allResolvedPackages := make([]YarnPackage, 0)

	for _, yarnPackage := range yarnPackages {
		if yarnPackage.Name == "__metadata" {
			continue
		}
		// Workspace packages have -use.local versions and workspace: resolutions
		if strings.Contains(yarnPackage.Version, yarnLocalVersionMarker) || strings.Contains(yarnPackage.Resolution, yarnWorkspaceResolutionMarker) {
			workspaces = append(workspaces, yarnPackage)
		} else {
			allResolvedPackages = append(allResolvedPackages, yarnPackage)
		}
	}

	dependencyWorkspaces := createDependencyWorkspaceMap(workspaces, allResolvedPackages)
	packages := createPackageDetails(allResolvedPackages, dependencyWorkspaces)

	pkgIndex := indexByNameAndVersions(packages)
	for index, pkg := range packages {
		packages[index].Dependencies = buildDependencyTree(pkg.Name, pkg.TargetVersions[0], "npm", yarnPackageIndex, pkgIndex)
	}

	return packages, nil
}

// Map to track which workspaces declare each dependency
// yarn lockfile represents as a flat list all dependencies, and we need to reconstruct which workspace declare which dependency
func createDependencyWorkspaceMap(workspaces []YarnPackage, allResolvedPackages []YarnPackage) map[string][]string {
	// First, build an index of workspace dependencies
	// Key: dependencyName@targetVersion, Value: workspace paths that declare it
	workspaceDepsIndex := make(map[string][]string)

	for _, workspace := range workspaces {
		workspacePath := workspace.WorkspacePath
		// "." is the value of the root workspace. Let's not use it -> default to empty string
		if workspacePath == "." {
			workspacePath = ""
		}

		for _, dep := range workspace.Dependencies {
			key := dep.Name + "@" + dep.Version
			workspaceDepsIndex[key] = append(workspaceDepsIndex[key], workspacePath)
		}
	}

	dependencyWorkspaces := make(map[string][]string)

	// Now iterate over resolved packages and lookup their workspace
	for _, pkg := range allResolvedPackages {
		// For the lookupKey, we use the pkg.TargetVersion and not pkg.Version because the dependencies
		// listed in the workspace.Dependencies are listed with the target versions, not the resolved versions
		// Meaning: pkg.TargetVersion == workspace.Dependencies.Version
		lookupKey := pkg.Name + "@" + pkg.TargetVersion
		if workspacePaths, exists := workspaceDepsIndex[lookupKey]; exists {
			depKey := getWorkspaceDependencyKey(pkg.Name, pkg.Version, pkg.TargetVersion)
			dependencyWorkspaces[depKey] = workspacePaths
		}
	}

	return dependencyWorkspaces
}

func createPackageDetails(allResolvedPackages []YarnPackage, dependencyWorkspaces map[string][]string) []lockfile.PackageDetails {
	packages := make([]lockfile.PackageDetails, 0, len(allResolvedPackages))

	// Create lockfile.PackageDetails for regular packages, with workspace information where applicable
	for _, yarnPackage := range allResolvedPackages {
		basePackage := parseYarnPackage(yarnPackage)
		depKey := getWorkspaceDependencyKey(yarnPackage.Name, yarnPackage.Version, yarnPackage.TargetVersion)

		if workspacePaths, exists := dependencyWorkspaces[depKey]; exists {
			// Create separate lockfile.PackageDetails for each workspace that declares this dependency with this target version
			// This is required to parse the related <workspace>/package.json and report an accurate location
			// The duplicates will each have a different location and will get merged before creating the SBOM
			for _, workspacePath := range workspacePaths {
				workspacePackage := basePackage
				if workspacePath != "" {
					workspacePackage.NameLocation = &models.FilePosition{Filename: workspacePath}
				}
				packages = append(packages, workspacePackage)
			}
		} else {
			// Regular package not declared by any workspace
			packages = append(packages, basePackage)
		}
	}

	return packages
}

var YarnExtractor = YarnLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageJSONMatcher{}}},
}

func ParseYarnLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, YarnExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.YarnFilePath, YarnExtractor)
}
