package javascript

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"

	jsonUtils "github.com/DataDog/datadog-sbom-generator/internal/json"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/bmatcuk/doublestar/v4"
)

func (m PackageJSONMatcher) GetSourceFile(depFile extractor.DepFile) (extractor.DepFile, error) {
	return depFile.Open("package.json")
}

func (depMap *packageJSONDependencyMap) UnmarshalJSON(data []byte) error {
	packageJSONContent := string(data)

	// Parse dependencies in incoming data
	var parsed map[string]interface{}
	unmarshallErr := json.Unmarshal(data, &parsed)
	if unmarshallErr != nil {
		depMap.reporter.Warnf("could not unmarshal %s, received error of %s", packageJSONContent, unmarshallErr)
	}

	dependencyNames := make(map[string]bool)
	for name := range parsed {
		dependencyNames[name] = true
	}

	for _, pkg := range depMap.Packages {
		// Skip packages in lockfile that are not declared in current dependency section
		// If we fail to unmarshall just process as before
		if unmarshallErr == nil && !dependencyNames[pkg.Name] {
			continue
		}

		var pkgIndexes []int

		for _, targetedVersion := range pkg.TargetVersions {
			pkgIndexes = jsonUtils.ExtractPackageIndexes(pkg.Name, targetedVersion, packageJSONContent)
			if len(pkgIndexes) > 0 {
				break
			}
		}

		// The matcher hasn't found package information, lets skip it
		if len(pkgIndexes) == 0 {
			continue
		}
		var depGroup string
		switch depMap.RootType {
		case typeDependencies:
			depGroup = "prod"
		case typeDevDependencies:
			depGroup = "dev"
		case typeOptionalDependencies:
			depGroup = "optional"
		}

		if (depMap.RootType == typeDevDependencies || depMap.RootType == typeOptionalDependencies) && pkg.LocationRole == models.LocationRoleManifest {
			// If it is a dev or optional dependency definition and this package was already
			// matched to a manifest location (e.g. the root package.json "dependencies" section,
			// or an earlier workspace package.json), skip the overwrite to prioritize the
			// non-dev/non-optional manifest location.
			// We check LocationRole rather than BlockLocation.Filename so that cross-workspace
			// matches are also guarded: a root prod-dep match sets LocationRole=manifest, and
			// a subsequent workspace dev-dep section for the same package must not overwrite it.
			pkgIndexes = []int{}
		}
		depMap.UpdatePackageDetails(pkg, packageJSONContent, pkgIndexes, depGroup)
	}

	return nil
}

func globWorkspacePackageJsons(workspacePatterns []string, basePath string) []string {
	var packageJSONFilePaths []string
	// Create a filesystem rooted at the directory containing basePath
	baseDir := filepath.Dir(basePath)
	fsys := os.DirFS(baseDir)

	for _, pattern := range workspacePatterns {
		// Convert npm workspace pattern to package.json file pattern
		// When we pass the pattern to doublestar.Glob, we need to ensure
		// it uses forward slashes as path separators, regardless of OS
		searchPattern := path.Join(pattern, "package.json")

		// Use the new function signature with the filesystem
		matches, err := doublestar.Glob(fsys, searchPattern)
		if err != nil {
			continue
		}

		packageJSONFilePaths = append(packageJSONFilePaths, matches...)
	}

	slices.Sort(packageJSONFilePaths)

	return packageJSONFilePaths
}

/*
Match works by leveraging the json decoder to only parse json sections of interest (e.g dependencies)
Whenever the json decoder try to deserialize a file, it will look at json sections it needs to deserialize
and then call the proper UnmarshallJSON method of the type. As the JSON decoder expect us to only deserialize it,
not trying to find the exact location in the file of the content, it does not provide us buffer information (offset, file path, etc...)

To work around this limitation, we are pre-filling the structure with all the field we will need during the deserialization :
  - The root type to know which json section we are deserializing
  - The file path to be able to fill properly location fields of extractor.PackageDetails
  - The line offset to be able to compute the line of any found dependencies in the file
  - And a list of pointer to the original extractor.PackageDetails extracted by the parser to be able to modify them with the json section content
*/
func (m PackageJSONMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	content, err := io.ReadAll(sourceFile)
	if err != nil {
		return err
	}

	// Group package indices by their NameLocation.filename for efficient matching
	packageIndicesByLocation := make(map[string][]int)
	var packagesWithoutKnownLocationIndices []int

	for i, pkg := range packages {
		// We check if we happen to already have information about where the package is coming from
		// When parsing package-lock.json, we would report known workspace location of the package
		// If we don't have any, it means the package is a root-level package
		if pkg.NameLocation == nil || pkg.NameLocation.Filename == "" {
			// Root-level packages (no specific workspace location)
			packagesWithoutKnownLocationIndices = append(packagesWithoutKnownLocationIndices, i)
		} else {
			// Workspace-specific packages
			workspacePath := filepath.FromSlash(pkg.NameLocation.Filename)
			packageIndicesByLocation[workspacePath] = append(packageIndicesByLocation[workspacePath], i)
		}
	}

	// Match root package.json with root-level packages
	if len(packagesWithoutKnownLocationIndices) > 0 {
		err = m.matchFileWithIndices(sourceFile, packages, packagesWithoutKnownLocationIndices, content, context.Reporter)
		if err != nil {
			return err
		}
	}

	var workspacesJSON WorkspacePackageJSON
	if err := json.Unmarshal(content, &workspacesJSON); err != nil {
		// If no workspaces, try matching all packages against root
		if len(packagesWithoutKnownLocationIndices) == 0 && len(packages) > 0 {
			err = m.matchFile(sourceFile, packages, content, context.Reporter)
			if err != nil {
				return err
			}
		}

		return nil
	}

	// Find and match each workspaces package.json file
	if len(workspacesJSON.Workspaces) > 0 {
		matches := globWorkspacePackageJsons(workspacesJSON.Workspaces, sourceFile.Path())

		// Match workspace-specific packages
		for workspacePath, indices := range packageIndicesByLocation {
			for _, match := range matches {
				matchPath := filepath.Dir(match)
				if matchPath == workspacePath {
					m.matchWorkspaceFile(sourceFile, match, packages, indices, context.Reporter)
				}
			}
		}

		if len(packagesWithoutKnownLocationIndices) > 0 {
			// If there are workspaces, then try to match the packages without a known location against the different <workspaces>/package.json
			m.matchPackagesWithoutKnownLocation(sourceFile, matches, packages, packagesWithoutKnownLocationIndices, context)
		}
	}

	return nil
}

func (m PackageJSONMatcher) matchFile(file extractor.DepFile, packages []extractor.PackageDetails, content []byte, r reporter.Reporter) error {
	allIndices := make([]int, len(packages))
	for i := range packages {
		allIndices[i] = i
	}

	return m.matchFileWithIndices(file, packages, allIndices, content, r)
}

func (m PackageJSONMatcher) matchFileWithIndices(file extractor.DepFile, allPackages []extractor.PackageDetails, indices []int, content []byte, r reporter.Reporter) error {
	contentStr := string(content)
	jsonFile := m.createPackageJSONFile(file, contentStr, r)

	// Create pointers only to the packages at specified indices
	packagesPtr := make([]*extractor.PackageDetails, len(indices))
	for i, idx := range indices {
		packagesPtr[i] = &allPackages[idx]
	}

	jsonFile.Dependencies.Packages = packagesPtr
	jsonFile.DevDependencies.Packages = packagesPtr
	jsonFile.OptionalDependencies.Packages = packagesPtr

	return json.Unmarshal(content, &jsonFile)
}

func (m PackageJSONMatcher) matchWorkspaceFile(sourcefile extractor.DepFile, match string, packages []extractor.PackageDetails, indices []int, r reporter.Reporter) {
	workspacePkg, err := sourcefile.Open(match)
	if err != nil {
		return
	}
	defer workspacePkg.Close()

	workspaceContent, err := io.ReadAll(workspacePkg)
	if err != nil {
		return
	}

	_ = m.matchFileWithIndices(workspacePkg, packages, indices, workspaceContent, r)
}

func (m PackageJSONMatcher) matchPackagesWithoutKnownLocation(sourcefile extractor.DepFile, matches []string, packages []extractor.PackageDetails, packagesWithoutKnownLocationIndices []int, context extractor.ScanContext) {
	for _, match := range matches {
		workspacePkg, err := sourcefile.Open(match)
		if err != nil {
			context.Reporter.Errorf("Failed to open workspace: %s from %s\n", match, sourcefile.Path())
			continue
		}

		workspaceContent, err := io.ReadAll(workspacePkg)
		workspacePkg.Close()
		if err != nil {
			context.Reporter.Errorf("Failed to open workspace: %s\n", workspacePkg)
			continue
		}

		_ = m.matchFileWithIndices(workspacePkg, packages, packagesWithoutKnownLocationIndices, workspaceContent, context.Reporter)
	}
}

func (m PackageJSONMatcher) createPackageJSONFile(file extractor.DepFile, contentStr string, r reporter.Reporter) packageJSONFile {
	effectiveReporter := reporter.Effective(r)
	return packageJSONFile{
		Dependencies: packageJSONDependencyMap{
			MatcherDependencyMap: extractor.MatcherDependencyMap{
				RootType:   typeDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("dependencies", contentStr),
			},
			reporter: effectiveReporter,
		},
		DevDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: extractor.MatcherDependencyMap{
				RootType:   typeDevDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("devDependencies", contentStr),
			},
			reporter: effectiveReporter,
		},
		OptionalDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: extractor.MatcherDependencyMap{
				RootType:   typeOptionalDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("optionalDependencies", contentStr),
			},
			reporter: effectiveReporter,
		},
	}
}

var _ extractor.Matcher = PackageJSONMatcher{}
