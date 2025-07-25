package lockfile

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	jsonUtils "github.com/DataDog/datadog-sbom-generator/internal/json"

	"github.com/bmatcuk/doublestar/v4"
)

const (
	typeDependencies = iota
	typeDevDependencies
	typeOptionalDependencies
)

type PackageJSONMatcher struct {
	// Used to store the patterns for workspaces in a given root package.json
	WorkspacePatterns []string
}

type WorkspacePackageJSON struct {
	Workspaces []string `json:"workspaces"`
}

/*
packageJSONDependencyMap is here to have access to all MatcherDependencyMap methods and at the same time having
a different type to have a clear UnmarshallJSON method for the json decoder and avoid overlaps with other matchers.
*/
type packageJSONDependencyMap struct {
	MatcherDependencyMap
}

type packageJSONFile struct {
	Dependencies         packageJSONDependencyMap `json:"dependencies"`
	DevDependencies      packageJSONDependencyMap `json:"devDependencies"`
	OptionalDependencies packageJSONDependencyMap `json:"optionalDependencies"`
}

func (m PackageJSONMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("package.json")
}

func (depMap *packageJSONDependencyMap) UnmarshalJSON(data []byte) error {
	content := string(data)

	for _, pkg := range depMap.Packages {
		var pkgIndexes []int

		for _, targetedVersion := range pkg.TargetVersions {
			pkgIndexes = jsonUtils.ExtractPackageIndexes(pkg.Name, targetedVersion, content)
			if len(pkgIndexes) > 0 {
				break
			}
		}

		if len(pkgIndexes) == 0 {
			// The matcher haven't found package information, lets skip it
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

		if (depMap.RootType == typeDevDependencies || depMap.RootType == typeOptionalDependencies) && pkg.BlockLocation.Line.Start != 0 {
			// If it is a dev or optional dependency definition and we already found a package location,
			// we skip it to prioritize non-dev dependencies
			pkgIndexes = []int{}
		}
		depMap.UpdatePackageDetails(pkg, content, pkgIndexes, depGroup)
	}

	return nil
}

// optimizeWorkspacePatterns removes redundant patterns and combines overlapping ones
func optimizeWorkspacePatterns(patterns []string) []string {
	if len(patterns) <= 1 {
		return patterns
	}

	// Remove exact duplicates
	seen := make(map[string]bool)
	unique := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if !seen[pattern] {
			seen[pattern] = true
			unique = append(unique, pattern)
		}
	}

	// Sort patterns by specificity (shorter patterns first, fewer wildcards first)
	// This helps identify when more specific patterns are subsumed by general ones
	optimized := make([]string, 0, len(unique))
	for _, pattern := range unique {
		isSubsumed := false
		for _, existing := range optimized {
			// Check if this pattern would be covered by an existing broader pattern
			if isPatternSubsumed(pattern, existing) {
				isSubsumed = true
				break
			}
		}
		if !isSubsumed {
			// Remove any existing patterns that would be subsumed by this new one
			filtered := make([]string, 0, len(optimized))
			for _, existing := range optimized {
				if !isPatternSubsumed(existing, pattern) {
					filtered = append(filtered, existing)
				}
			}
			filtered = append(filtered, pattern)
			optimized = filtered
		}
	}

	return optimized
}

// isPatternSubsumed checks if pattern1 would be covered by pattern2
func isPatternSubsumed(pattern1, pattern2 string) bool {
	// Handle the case where one pattern is a more general version of another
	// e.g., "packages/apps/**" subsumes "packages/apps/*/*"
	
	// Convert patterns to comparable forms by replacing multiple * with **
	normalizePattern := func(p string) string {
		// Replace sequences like "/*/*/*" with "/**"
		for strings.Contains(p, "/*/*") {
			p = strings.ReplaceAll(p, "/*/*", "/**")
		}
		return p
	}
	
	norm1 := normalizePattern(pattern1)
	norm2 := normalizePattern(pattern2)
	
	// If pattern2 ends with ** and pattern1 starts with the same prefix
	if strings.HasSuffix(norm2, "/**") {
		prefix := strings.TrimSuffix(norm2, "/**")
		if strings.HasPrefix(norm1, prefix) && len(norm1) > len(norm2) {
			return true
		}
	}
	
	// Also check the reverse - if pattern1 is more general than pattern2
	if strings.HasSuffix(norm1, "/**") {
		prefix := strings.TrimSuffix(norm1, "/**")
		if strings.HasPrefix(norm2, prefix) && len(norm2) > len(norm1) {
			return false // pattern2 is more specific, don't subsume
		}
	}
	
	return false
}

func globWorkspacePackageJsons(workspacePatterns []string, basePath string) []string {
	// Optimize patterns to reduce redundant filesystem operations
	optimizedPatterns := optimizeWorkspacePatterns(workspacePatterns)
	
	var packageJSONFilePaths []string

	// Create a filesystem rooted at the directory containing basePath
	baseDir := filepath.Dir(basePath)
	fsys := os.DirFS(baseDir)

	for _, pattern := range optimizedPatterns {
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

	return packageJSONFilePaths
}

/*
Match works by leveraging the json decoder to only parse json sections of interest (e.g dependencies)
Whenever the json decoder try to deserialize a file, it will look at json sections it needs to deserialize
and then call the proper UnmarshallJSON method of the type. As the JSON decoder expect us to only deserialize it,
not trying to find the exact location in the file of the content, it does not provide us buffer information (offset, file path, etc...)

To work around this limitation, we are pre-filling the structure with all the field we will need during the deserialization :
  - The root type to know which json section we are deserializing
  - The file path to be able to fill properly location fields of PackageDetails
  - The line offset to be able to compute the line of any found dependencies in the file
  - And a list of pointer to the original PackageDetails extracted by the parser to be able to modify them with the json section content
*/
func (m PackageJSONMatcher) Match(sourcefile DepFile, packages []PackageDetails) error {
	content, err := io.ReadAll(sourcefile)
	if err != nil {
		return err
	}

	// Match root package.json
	err = m.matchFile(sourcefile, packages, content)
	if err != nil {
		return err
	}

	var workspacesJSON WorkspacePackageJSON
	if err := json.Unmarshal(content, &workspacesJSON); err != nil {
		err = m.matchFile(sourcefile, packages, content)
		if err != nil {
			return err
		}

		return nil
	}

	// Find and match each workspaces package.json file
	if len(workspacesJSON.Workspaces) > 0 {
		matches := globWorkspacePackageJsons(workspacesJSON.Workspaces, sourcefile.Path())

		for _, match := range matches {
			workspacePkg, err := sourcefile.Open(match)
			if err != nil {
				continue
			}
			defer workspacePkg.Close()

			workspaceContent, err := io.ReadAll(workspacePkg)
			if err != nil {
				continue
			}

			// Match dependencies in workspace package.json
			if err := m.matchFile(workspacePkg, packages, workspaceContent); err != nil {
				continue
			}
		}
	}

	return nil
}

func (m PackageJSONMatcher) matchFile(file DepFile, packages []PackageDetails, content []byte) error {
	contentStr := string(content)
	dependenciesLineOffset := jsonUtils.GetSectionOffset("dependencies", contentStr)
	devDependenciesLineOffset := jsonUtils.GetSectionOffset("devDependencies", contentStr)
	optionalDepenenciesLineOffset := jsonUtils.GetSectionOffset("optionalDependencies", contentStr)

	jsonFile := packageJSONFile{
		Dependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeDependencies,
				FilePath:   file.Path(),
				LineOffset: dependenciesLineOffset,
			},
		},
		DevDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeDevDependencies,
				FilePath:   file.Path(),
				LineOffset: devDependenciesLineOffset,
			},
		},
		OptionalDependencies: packageJSONDependencyMap{
			MatcherDependencyMap: MatcherDependencyMap{
				RootType:   typeOptionalDependencies,
				FilePath:   file.Path(),
				LineOffset: optionalDepenenciesLineOffset,
			},
		},
	}
	packagesPtr := make([]*PackageDetails, len(packages))
	for index := range packages {
		packagesPtr[index] = &packages[index]
	}
	jsonFile.Dependencies.Packages = packagesPtr
	jsonFile.DevDependencies.Packages = packagesPtr
	jsonFile.OptionalDependencies.Packages = packagesPtr

	return json.Unmarshal(content, &jsonFile)
}

var _ Matcher = PackageJSONMatcher{}
