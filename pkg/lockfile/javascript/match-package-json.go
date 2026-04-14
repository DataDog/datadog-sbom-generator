package javascript

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"slices"

	jsonUtils "github.com/DataDog/datadog-sbom-generator/internal/json"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/bmatcuk/doublestar/v4"
)

func (m PackageJSONMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("package.json")
}

func (depMap *packageJSONDependencyMap) UnmarshalJSON(data []byte) error {
	packageJSONContent := string(data)

	// Parse dependencies in incoming data
	var parsed map[string]interface{}
	unmarshallErr := json.Unmarshal(data, &parsed)
	if unmarshallErr != nil {
		log.Printf("could not unmarshal %s, received error of %s", packageJSONContent, unmarshallErr)
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

		if (depMap.RootType == typeDevDependencies || depMap.RootType == typeOptionalDependencies) && pkg.BlockLocation.Filename == depMap.FilePath {
			// If it is a dev or optional dependency definition and this package's BlockLocation
			// already points to the current source file (meaning a prior matcher section like
			// "dependencies" already set it), skip the location overwrite to prioritize the
			// non-dev location. We compare Filename rather than checking Line.Start != 0
			// because extractors may now set BlockLocation from the lockfile for all packages.
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
  - The file path to be able to fill properly location fields of lockfile.PackageDetails
  - The line offset to be able to compute the line of any found dependencies in the file
  - And a list of pointer to the original lockfile.PackageDetails extracted by the parser to be able to modify them with the json section content
*/
func (m PackageJSONMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
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
		err = m.matchFileWithIndices(sourceFile, packages, packagesWithoutKnownLocationIndices, content)
		if err != nil {
			return err
		}
	}

	var workspacesJSON WorkspacePackageJSON
	if err := json.Unmarshal(content, &workspacesJSON); err != nil {
		// If no workspaces, try matching all packages against root
		if len(packagesWithoutKnownLocationIndices) == 0 && len(packages) > 0 {
			err = m.matchFile(sourceFile, packages, content)
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
					m.matchWorkspaceFile(sourceFile, match, packages, indices)
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

func (m PackageJSONMatcher) matchFile(file lockfile.DepFile, packages []lockfile.PackageDetails, content []byte) error {
	allIndices := make([]int, len(packages))
	for i := range packages {
		allIndices[i] = i
	}

	return m.matchFileWithIndices(file, packages, allIndices, content)
}

func (m PackageJSONMatcher) matchFileWithIndices(file lockfile.DepFile, allPackages []lockfile.PackageDetails, indices []int, content []byte) error {
	contentStr := string(content)
	jsonFile := m.createPackageJSONFile(file, contentStr)

	// Create pointers only to the packages at specified indices
	packagesPtr := make([]*lockfile.PackageDetails, len(indices))
	for i, idx := range indices {
		packagesPtr[i] = &allPackages[idx]
	}

	jsonFile.Dependencies.Packages = packagesPtr
	jsonFile.DevDependencies.Packages = packagesPtr
	jsonFile.OptionalDependencies.Packages = packagesPtr

	return json.Unmarshal(content, &jsonFile)
}

func (m PackageJSONMatcher) matchWorkspaceFile(sourcefile lockfile.DepFile, match string, packages []lockfile.PackageDetails, indices []int) {
	workspacePkg, err := sourcefile.Open(match)
	if err != nil {
		return
	}
	defer workspacePkg.Close()

	workspaceContent, err := io.ReadAll(workspacePkg)
	if err != nil {
		return
	}

	_ = m.matchFileWithIndices(workspacePkg, packages, indices, workspaceContent)
}

func (m PackageJSONMatcher) matchPackagesWithoutKnownLocation(sourcefile lockfile.DepFile, matches []string, packages []lockfile.PackageDetails, packagesWithoutKnownLocationIndices []int, context lockfile.ScanContext) {
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

		_ = m.matchFileWithIndices(workspacePkg, packages, packagesWithoutKnownLocationIndices, workspaceContent)
	}
}

func (m PackageJSONMatcher) createPackageJSONFile(file lockfile.DepFile, contentStr string) packageJSONFile {
	return packageJSONFile{
		Dependencies: packageJSONDependencyMap{
			MatcherDependencyMap: lockfile.MatcherDependencyMap{
				RootType:   typeDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("dependencies", contentStr),
			},
		},
		DevDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: lockfile.MatcherDependencyMap{
				RootType:   typeDevDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("devDependencies", contentStr),
			},
		},
		OptionalDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: lockfile.MatcherDependencyMap{
				RootType:   typeOptionalDependencies,
				FilePath:   file.Path(),
				LineOffset: jsonUtils.GetSectionOffset("optionalDependencies", contentStr),
			},
		},
	}
}

var _ lockfile.Matcher = PackageJSONMatcher{}
