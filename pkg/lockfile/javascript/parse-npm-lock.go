package javascript

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
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/bmatcuk/doublestar/v4"
)

const (
	npmPackageManager      = models.NPM
	npmOfficiallySupported = true
	nodeModulesPath        = "node_modules/"
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

type npmPackageDetailsMap map[string]lockfile.PackageDetails

// mergeNpmDepsGroups handles merging the dependency groups of packages within the
// NPM ecosystem, since they can appear multiple times in the same dependency tree
//
// the merge happens almost as you'd expect, except that if either given packages
// belong to no groups, then that is the result since it indicates the package
// is implicitly a production dependency.
func mergeNpmDepsGroups(a, b lockfile.PackageDetails) []string {
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

func (pdm npmPackageDetailsMap) add(key string, details lockfile.PackageDetails) {
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

func parseNpmLockDependencies(dependencies map[string]*NpmLockDependency) map[string]lockfile.PackageDetails {
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

		details.add(name+"@"+version, lockfile.PackageDetails{
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

func extractWorkspacePatterns(packages map[string]*NpmLockPackage) []string {
	rootPkg, hasRootPkg := packages[""]
	var workspacePatterns []string
	if hasRootPkg {
		workspacePatterns = rootPkg.Workspaces
	}

	return workspacePatterns
}

func getWorkspaceResolvedPath(workspacePath string, depName string) string {
	return workspacePath + "/" + nodeModulesPath + depName
}

func getRootResolvedPath(depName string) string {
	return nodeModulesPath + depName
}

// Pre-compute maps for lookups
type categorizedPackages struct {
	Resolved          map[string]*NpmLockPackage // resolved / downloaded packages (downloaded to node_modules)
	DeclaredRoot      map[string]string          // declared packages in <root>/package.json
	DeclaredWorkspace map[string]*NpmLockPackage // declared workspace packages in <workspace>/package.json
	Local             map[string]*NpmLockPackage
}

func categorizePackages(packages map[string]*NpmLockPackage, workspacePatterns []string) categorizedPackages {
	resolvedPackages := make(map[string]*NpmLockPackage)
	declaredRootPackages := make(map[string]string)
	declaredWorkspacePackages := make(map[string]*NpmLockPackage)
	localPackages := make(map[string]*NpmLockPackage)

	for packagePath, pkg := range packages {
		if packagePath == "" {
			for name, version := range pkg.Dependencies {
				declaredRootPackages[name] = version
			}
			for name, version := range pkg.DevDependencies {
				declaredRootPackages[name] = version
			}
			for name, version := range pkg.OptionalDependencies {
				declaredRootPackages[name] = version
			}

			continue
		}

		if pkg.Link {
			continue
		}

		// Packages with a path containing "node_modules/" are the actual downloaded packages
		if strings.Contains(packagePath, nodeModulesPath) || strings.HasPrefix(packagePath, nodeModulesPath) {
			resolvedPackages[packagePath] = pkg
		} else if matchesWorkspacePattern(workspacePatterns, packagePath) {
			declaredWorkspacePackages[packagePath] = pkg
		} else {
			localPackages[packagePath] = pkg
		}
	}

	return categorizedPackages{
		Resolved:          resolvedPackages,
		DeclaredRoot:      declaredRootPackages,
		DeclaredWorkspace: declaredWorkspacePackages,
		Local:             localPackages,
	}
}

func processWorkspacePackages(
	details npmPackageDetailsMap,
	declaredWorkspacePackages map[string]*NpmLockPackage,
	resolvedPackages map[string]*NpmLockPackage,
	processedPackages *map[string]bool,
) {
	for workspacePath, workspacePkg := range declaredWorkspacePackages {
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

		// For declared packages in workspaces, try to find the related resolved package (the actual downloaded node_modules)
		for depName, targetVersion := range allDeps {
			workspaceNodeModulesPath := getWorkspaceResolvedPath(workspacePath, depName)
			params := packageProcessingParams{
				Details:           details,
				DepName:           depName,
				TargetVersion:     targetVersion,
				DeclarationPath:   workspacePath,
				ProcessedPackages: processedPackages,
			}

			if resolvedPkg, exists := resolvedPackages[workspaceNodeModulesPath]; exists {
				params.PhysicalPath = workspaceNodeModulesPath
				params.Pkg = resolvedPkg
				processPackage(params)
			} else {
				// When resolving dependency, if a dependency only exist in a workspace, NPM would reference the library
				// as a root node_modules. And not as a workspace dependency! That's why we fall back looking for root.
				rootNodeModulesPath := getRootResolvedPath(depName)
				if resolvedPkg, exists := resolvedPackages[rootNodeModulesPath]; exists {
					params.PhysicalPath = rootNodeModulesPath
					params.Pkg = resolvedPkg
					processPackage(params)
				} else {
					// Dependency not found in either workspace or root node_modules,
					// This could indicate a malformed lockfile or a dependency added to package.json without running 'npm install'
					continue
				}
			}
		}
	}
}

func processRootPackages(
	details npmPackageDetailsMap,
	declaredRootPackages map[string]string,
	resolvedPackages map[string]*NpmLockPackage,
	processedPackages *map[string]bool,
) {
	for depName, targetVersion := range declaredRootPackages {
		rootNodeModulesPath := getRootResolvedPath(depName)
		if resolvedPkg, exists := resolvedPackages[rootNodeModulesPath]; exists {
			processPackage(packageProcessingParams{
				Details:           details,
				DepName:           depName,
				Pkg:               resolvedPkg,
				TargetVersion:     targetVersion,
				DeclarationPath:   "",
				PhysicalPath:      rootNodeModulesPath,
				ProcessedPackages: processedPackages,
			})
		}
	}
}

func processLocalPackages(
	details npmPackageDetailsMap,
	localPackages map[string]*NpmLockPackage,
	declaredRootPackages map[string]string,
	processedPackages *map[string]bool,
) {
	for localPath, localPkg := range localPackages {
		depName := path.Base(localPath)
		var targetVersion string
		for name, version := range declaredRootPackages {
			if name == depName {
				targetVersion = version
				break
			}
		}
		processPackage(packageProcessingParams{
			Details:           details,
			DepName:           depName,
			Pkg:               localPkg,
			TargetVersion:     targetVersion,
			DeclarationPath:   "",
			PhysicalPath:      localPath,
			ProcessedPackages: processedPackages,
		})
	}
}

func processRemainingPackages(
	details npmPackageDetailsMap,
	resolvedPackages map[string]*NpmLockPackage,
	processedPackages *map[string]bool,
) {
	for physicalPath, pkg := range resolvedPackages {
		if !(*processedPackages)[physicalPath] {
			depName := extractNpmPackageName(physicalPath)
			processPackage(packageProcessingParams{
				Details:           details,
				DepName:           depName,
				Pkg:               pkg,
				TargetVersion:     "",
				DeclarationPath:   "",
				PhysicalPath:      physicalPath,
				ProcessedPackages: processedPackages,
			})
		}
	}
}

type packageProcessingParams struct {
	Details           npmPackageDetailsMap
	DepName           string
	Pkg               *NpmLockPackage
	TargetVersion     string
	DeclarationPath   string
	PhysicalPath      string
	ProcessedPackages *map[string]bool
}

func processPackage(params packageProcessingParams) {
	finalName := params.Pkg.Name
	if finalName == "" {
		finalName = params.DepName
	}

	finalVersion := params.Pkg.Version
	commit := tryExtractCommit(params.Pkg.Resolved)

	if commit != "" {
		finalVersion = commit
	}

	if finalVersion == "" {
		params.Pkg.Version = "0.0.0"
		finalVersion = "0.0.0"
	}

	var targetVersions []string
	if params.TargetVersion != "" {
		// Clean aliased target version
		targetVersion := params.TargetVersion
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

	// A given package can be declared in multiple places, we want to track the declaration paths so that we know which one to match
	if params.DeclarationPath != "" {
		location = &models.FilePosition{Filename: params.DeclarationPath}
	}

	packageUniqKey := getWorkspaceDependencyKey(finalName, finalVersion, params.DeclarationPath)
	params.Details.add(packageUniqKey, lockfile.PackageDetails{
		Name:           finalName,
		Version:        params.Pkg.Version,
		TargetVersions: targetVersions,
		PackageManager: npmPackageManager,
		Ecosystem:      models.EcosystemNPM,
		Commit:         commit,
		DepGroups:      params.Pkg.depGroups(),
		NameLocation:   location,
	})

	// Mark as processed
	(*params.ProcessedPackages)[params.PhysicalPath] = true
}

func parseNpmLockPackages(packages map[string]*NpmLockPackage) map[string]lockfile.PackageDetails {
	details := npmPackageDetailsMap{}

	workspacePatterns := extractWorkspacePatterns(packages)
	categorized := categorizePackages(packages, workspacePatterns)

	processedPackages := make(map[string]bool) // makes sure we do not process the same package twice (meaningful with the support of workspaces)

	processRootPackages(details, categorized.DeclaredRoot, categorized.Resolved, &processedPackages)
	processWorkspacePackages(details, categorized.DeclaredWorkspace, categorized.Resolved, &processedPackages)
	processLocalPackages(details, categorized.Local, categorized.DeclaredRoot, &processedPackages)
	processRemainingPackages(details, categorized.Resolved, &processedPackages)

	return details
}

func parseNpmLock(lockfile NpmLockfile, lines []string) map[string]lockfile.PackageDetails {
	if lockfile.Packages != nil {
		fileposition.InJSON("packages", lockfile.Packages, lines, 0)

		return parseNpmLockPackages(lockfile.Packages)
	}

	fileposition.InJSON("dependencies", lockfile.Dependencies, lines, 0)

	return parseNpmLockDependencies(lockfile.Dependencies)
}

func getWorkspaceDependencyKey(pkgName string, pkgVersion string, workspace string) string {
	key := pkgName + "@" + pkgVersion

	// Create workspace-specific key to keep workspace declarations separate
	if workspace != "" && workspace != "." {
		key += "@workspace:" + workspace
	}

	return key
}

type NpmLockExtractor struct {
	lockfile.WithMatcher
}

func (e NpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.NpmFilePath.String()
}

func (e NpmLockExtractor) IsOfficiallySupported() bool {
	return npmOfficiallySupported
}

func (e NpmLockExtractor) PackageManager() models.PackageManager {
	return npmPackageManager
}

func (e NpmLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *NpmLockfile

	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}
	contentString := string(contentBytes)
	lines := strings.Split(contentString, "\n")
	decoder := json.NewDecoder(strings.NewReader(contentString))

	if err := decoder.Decode(&parsedLockfile); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	parsedLockfile.SourceFile = f.Path()

	return slices.Collect(maps.Values(parseNpmLock(*parsedLockfile, lines))), nil
}

var NpmExtractor = NpmLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageJSONMatcher{}}},
}

func ParseNpmLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, NpmExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.NpmFilePath, NpmExtractor)
}
