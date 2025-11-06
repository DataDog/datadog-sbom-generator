package lockfile

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/bmatcuk/doublestar/v4"
)

const (
	npmPackageManager      = models.NPM
	npmFilePath            = models.NpmFilePath
	npmOfficiallySupported = true
)

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                        `json:"version"`
	Dependencies map[string]*NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`

	models.FilePosition
}

func (dep *NpmLockDependency) GetNestedDependencies() map[string]*models.FilePosition {
	result := make(map[string]*models.FilePosition)
	for key, value := range dep.Dependencies {
		result[key] = &value.FilePosition
	}

	return result
}

type NpmLockPackage struct {
	// For an aliased package, Name is the real package name
	Name     string `json:"name"`
	Version  string `json:"version"`
	Resolved string `json:"resolved"`

	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`

	Workspaces []string `json:"workspaces,omitempty"`

	Dev         bool `json:"dev,omitempty"`
	DevOptional bool `json:"devOptional,omitempty"`
	Optional    bool `json:"optional,omitempty"`

	Link bool `json:"link,omitempty"`

	models.FilePosition
}

type NpmLockfile struct {
	Version    int `json:"lockfileVersion"`
	SourceFile string
	// npm v1- lockfiles use "dependencies"
	Dependencies map[string]*NpmLockDependency `json:"dependencies"`
	// npm v2+ lockfiles use "packages"
	Packages map[string]*NpmLockPackage `json:"packages,omitempty"`
}

type npmPackageDetailsMap map[string]PackageDetails

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b PackageDetails) []string {
	// if either group includes no groups, then the package is in the "production" group
	if len(a.DepGroups) == 0 || len(b.DepGroups) == 0 {
		return nil
	}

	combined := make([]string, 0, len(a.DepGroups)+len(b.DepGroups))
	combined = append(combined, a.DepGroups...)
	combined = append(combined, b.DepGroups...)

	slices.Sort(combined)

	return slices.Compact(combined)
}

func (pdm npmPackageDetailsMap) add(key string, details PackageDetails) {
	existing, ok := pdm[key]

	if ok {
		details.DepGroups = mergeNpmDepsGroups(existing, details)
	}

	pdm[key] = details
}

func (dep *NpmLockDependency) depGroups() []string {
	groups := make([]string, 0)
	if dep.Optional {
		groups = append(groups, "optional")
	}
	if dep.Dev {
		groups = append(groups, "dev")
	} else {
		groups = append(groups, "prod")
	}

	return groups
}

func parseNpmLockDependencies(dependencies map[string]*NpmLockDependency) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

	keys := reflect.ValueOf(dependencies).MapKeys()
	keysOrder := func(i, j int) bool { return keys[i].Interface().(string) < keys[j].Interface().(string) }
	sort.Slice(keys, keysOrder)

	for _, key := range keys {
		name := key.Interface().(string)
		detail := dependencies[name]
		if detail.Dependencies != nil {
			nestedDeps := parseNpmLockDependencies(detail.Dependencies)
			for k, v := range nestedDeps {
				details.add(k, v)
			}
		}

		version := detail.Version
		finalVersion := version
		commit := ""

		// If the package is aliased, get the name and version
		if strings.HasPrefix(detail.Version, "npm:") {
			i := strings.LastIndex(detail.Version, "@")
			name = detail.Version[4:i]
			finalVersion = detail.Version[i+1:]
		}

		// we can't resolve a version from a "file:" dependency
		if strings.HasPrefix(detail.Version, "file:") {
			finalVersion = ""
			version = ""
		} else {
			commit = tryExtractCommit(detail.Version)

			// if there is a commit, we want to deduplicate based on that rather than
			// the version (the versions must match anyway for the commits to match)
			//
			// we also don't actually know what the "version" is, so blank it
			if commit != "" {
				finalVersion = ""
				version = commit
			}
		}

		details.add(name+"@"+version, PackageDetails{
			Name:           name,
			Version:        finalVersion,
			PackageManager: npmPackageManager,
			Ecosystem:      models.EcosystemNPM,
			Commit:         commit,
			DepGroups:      detail.depGroups(),
		})
	}

	return details
}

func extractNpmPackageName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}

func (pkg NpmLockPackage) depGroups() []string {
	groups := make([]string, 0)
	if pkg.Dev {
		groups = append(groups, "dev")
	}
	if pkg.Optional {
		groups = append(groups, "optional")
	}
	if pkg.DevOptional {
		groups = append(groups, "dev", "optional")
	}
	if !pkg.Dev && !pkg.DevOptional {
		groups = append(groups, "prod")
	}

	return groups
}

func matchesWorkspacePattern(patterns []string, testPath string) bool {
	for _, pattern := range patterns {
		if matched, _ := doublestar.Match(pattern, testPath); matched {
			return true
		}
	}

	return false
}

func parseNpmLockPackages(packages map[string]*NpmLockPackage) map[string]PackageDetails {
	details := npmPackageDetailsMap{}

	// Find workspace patterns from root package
	rootPkg, hasRootPkg := packages[""]
	var workspacePatterns []string
	if hasRootPkg {
		workspacePatterns = rootPkg.Workspaces
	}

	// Pre-compute maps for efficient lookups
	physicalPackages := make(map[string]*NpmLockPackage)  // node_modules paths (actual downloaded packages)
	workspacePackages := make(map[string]*NpmLockPackage) // workspace logical entries from package.json
	localPackages := make(map[string]*NpmLockPackage)     // local file dependencies
	rootDeps := make(map[string]string)                   // root-level dependencies
	processedPackages := make(map[string]bool)            // tracks already processed packages

	// Categorize packages for efficient lookup
	for packagePath, pkg := range packages {
		if packagePath == "" {
			// Collect root dependencies
			for name, version := range pkg.Dependencies {
				rootDeps[name] = version
			}
			for name, version := range pkg.DevDependencies {
				rootDeps[name] = version
			}
			for name, version := range pkg.OptionalDependencies {
				rootDeps[name] = version
			}
			continue
		}

		// Packages with 'link: true', are inner project workspace. We will read their dependencies directly
		if pkg.Link {
			continue
		}

		if strings.Contains(packagePath, "/node_modules/") || strings.HasPrefix(packagePath, "node_modules/") {
			physicalPackages[packagePath] = pkg
		} else if matchesWorkspacePattern(workspacePatterns, packagePath) {
			workspacePackages[packagePath] = pkg
		} else {
			// Local file dependencies (like "deps/etag")
			localPackages[packagePath] = pkg
		}
	}

	// 1. Process workspace logical entries first
	for workspacePath, workspacePkg := range workspacePackages {
		allDeps := make(map[string]string)
		for name, version := range workspacePkg.Dependencies {
			allDeps[name] = version
		}
		for name, version := range workspacePkg.DevDependencies {
			allDeps[name] = version
		}
		for name, version := range workspacePkg.OptionalDependencies {
			allDeps[name] = version
		}

		// For each logical dependency (declared in workspace package.json), 
		// find the corresponding physical package in node_modules
		for depName, targetVersion := range allDeps {
			// 2a. Check workspace-specific node_modules
			workspaceNodeModulesPath := workspacePath + "/node_modules/" + depName
			if physicalPkg, exists := physicalPackages[workspaceNodeModulesPath]; exists {
				processPackage(details, depName, physicalPkg, targetVersion, workspacePath, workspaceNodeModulesPath, &processedPackages)
			} else {
				// 2b. Check root node_modules
				// When resolving dependency, if a dependency only exist in a workspace, NPM would reference the library
				// as a root node_modules. And not as a workspace dependency! That's why we fall back looking for root.
				rootNodeModulesPath := "node_modules/" + depName
				if physicalPkg, exists := physicalPackages[rootNodeModulesPath]; exists {
					processPackage(details, depName, physicalPkg, targetVersion, workspacePath, rootNodeModulesPath, &processedPackages)
				} else {
					// 2c. Dependency not found in either workspace or root node_modules
					// This could indicate a malformed lockfile or missing dependency
					continue
				}
			}
		}
	}

	// 3. Process root logical entries
	for depName, targetVersion := range rootDeps {
		rootNodeModulesPath := "node_modules/" + depName
		if physicalPkg, exists := physicalPackages[rootNodeModulesPath]; exists {
			if !processedPackages[rootNodeModulesPath] {
				processPackage(details, depName, physicalPkg, targetVersion, "", rootNodeModulesPath, &processedPackages)
			}
		}
	}

	// 4. Process local file dependencies (non 3rd parties!)
	for localPath, localPkg := range localPackages {
		// Extract package name from path
		depName := path.Base(localPath)
		// Check if this is referenced in root dependencies
		var targetVersion string
		for name, version := range rootDeps {
			if name == depName {
				targetVersion = version
				break
			}
		}
		processPackage(details, depName, localPkg, targetVersion, "", localPath, &processedPackages)
	}

	// 5. Process remaining physical packages (transitive dependencies)
	for physicalPath, pkg := range physicalPackages {
		if !processedPackages[physicalPath] {
			depName := extractNpmPackageName(physicalPath)
			processPackage(details, depName, pkg, "", "", physicalPath, &processedPackages)
		}
	}

	return details
}

func processPackage(details npmPackageDetailsMap, depName string, pkg *NpmLockPackage, targetVersion string, workspacePath string, physicalPath string, processedPackages *map[string]bool) {
	finalName := pkg.Name
	if finalName == "" {
		finalName = depName
	}

	finalVersion := pkg.Version
	commit := tryExtractCommit(pkg.Resolved)

	if commit != "" {
		finalVersion = commit
	}

	if finalVersion == "" {
		pkg.Version = "0.0.0"
		finalVersion = "0.0.0"
	}

	var targetVersions []string
	if targetVersion != "" {
		// Clean aliased target version
		if strings.HasPrefix(targetVersion, "npm:") {
			_, targetVersion, _ = strings.Cut(targetVersion, "@")
		}

		// Clean prefixes
		prefixes := []string{"file", "link", "portal"}
		for _, prefix := range prefixes {
			if strings.HasPrefix(targetVersion, prefix+":") {
				targetVersion = strings.TrimPrefix(targetVersion, prefix+":")
				targetVersion = strings.TrimPrefix(targetVersion, "./")
			}
		}
		targetVersions = []string{targetVersion}
	}
	var location *models.FilePosition

	if workspacePath != "" {
		location = &models.FilePosition{Filename: workspacePath}
	}

	details.add(finalName+"@"+finalVersion, PackageDetails{
		Name:           finalName,
		Version:        pkg.Version,
		TargetVersions: targetVersions,
		PackageManager: npmPackageManager,
		Ecosystem:      models.EcosystemNPM,
		Commit:         commit,
		DepGroups:      pkg.depGroups(),
		NameLocation:   location,
	})

	// Mark as processed
	(*processedPackages)[physicalPath] = true
}

func parseNpmLock(lockfile NpmLockfile, lines []string) map[string]PackageDetails {
	if lockfile.Packages != nil {
		fileposition.InJSON("packages", lockfile.Packages, lines, 0)

		return parseNpmLockPackages(lockfile.Packages)
	}

	fileposition.InJSON("dependencies", lockfile.Dependencies, lines, 0)

	return parseNpmLockDependencies(lockfile.Dependencies)
}

type NpmLockExtractor struct {
	WithMatcher
}

func (e NpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == npmFilePath
}

func (e NpmLockExtractor) IsOfficiallySupported() bool {
	return npmOfficiallySupported
}

func (e NpmLockExtractor) PackageManager() models.PackageManager {
	return npmPackageManager
}

func (e NpmLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *NpmLockfile

	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}
	contentString := string(contentBytes)
	lines := strings.Split(contentString, "\n")
	decoder := json.NewDecoder(strings.NewReader(contentString))

	if err := decoder.Decode(&parsedLockfile); err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	parsedLockfile.SourceFile = f.Path()

	return slices.Collect(maps.Values(parseNpmLock(*parsedLockfile, lines))), nil
}

var NpmExtractor = NpmLockExtractor{
	WithMatcher{Matchers: []Matcher{&PackageJSONMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("package-lock.json", NpmExtractor)
}

func ParseNpmLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, NpmExtractor)
}
