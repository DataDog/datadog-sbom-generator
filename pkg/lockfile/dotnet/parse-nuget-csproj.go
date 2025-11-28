package dotnet

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e NuGetCsprojExtractor) ShouldExtract(path string) bool {
	if !strings.HasSuffix(path, "."+models.NuGetCsProjFilePath.String()) {
		return false
	}

	// Only use csproj extractor if packages.lock.json doesn't exist
	// This makes csproj a fallback when the lock file is not available
	dir := filepath.Dir(path)
	lockfilePath := filepath.Join(dir, models.NugetLockFilePath.String())

	if _, err := os.Stat(lockfilePath); err == nil {
		// Lock file exists, don't use csproj extractor
		return false
	}

	return true
}

// ParseNugetCsProj parses a .csproj file and returns a map of package references by package name.
// This is shared logic used by both the extractor and matcher.
func ParseNugetCsProj(content []byte, csprojPath string) (*ParsedCsProj, error) {
	var project NugetCsProj
	err := xml.Unmarshal(content, &project)
	if err != nil {
		return nil, err
	}

	packageReferenceByInclude := make(map[string]PackageReference)
	for _, itemGroup := range project.ItemGroups {
		for _, packageReference := range itemGroup.PackageReferences {
			include := GetInclude(packageReference)
			if include != "" {
				packageReferenceByInclude[include] = packageReference
			}
		}
	}

	// Build property map from the PropertyGroups of the current .csproj
	localProperties := buildPropertyMap(project.PropertyGroups)

	// Discover and parse .props files recursively, merging properties as we go
	mergedProperties := traverseAndMergePropsFiles(csprojPath, project.Imports, localProperties)

	return &ParsedCsProj{
		PackagesByName:   packageReferenceByInclude,
		PropertiesByName: mergedProperties,
	}, nil
}

func (e NuGetCsprojExtractor) IsOfficiallySupported() bool {
	return nugetOfficiallySupported
}

func (e NuGetCsprojExtractor) PackageManager() models.PackageManager {
	return nugetPackageManager
}

func (e NuGetCsprojExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	parsedCsProj, err := ParseNugetCsProj(content, f.Path())
	if err != nil {
		return nil, fmt.Errorf("could not parse csproj %s: %w", f.Path(), err)
	}
	packageReferences := parsedCsProj.PackagesByName
	allProperties := parsedCsProj.PropertiesByName

	lines := fileposition.BytesToLines(content)
	details := make([]lockfile.PackageDetails, 0, len(packageReferences))

	for name, pkgRef := range packageReferences {
		version := GetVersion(pkgRef, allProperties)

		if version == "" {
			// Skip packages without explicit versions - they might use
			// centralized version management or other mechanisms
			continue
		}

		depGroup := models.DepGroupProd
		if IsDevDependency(pkgRef) {
			depGroup = models.DepGroupDev
		}

		block := lines[pkgRef.Line.Start-1 : pkgRef.Line.End]

		blockLocation := models.FilePosition{
			Line:     models.Position{Start: pkgRef.Line.Start, End: pkgRef.Line.End},
			Column:   models.Position{Start: pkgRef.Column.Start, End: pkgRef.Column.End},
			Filename: f.Path(),
		}

		nameLocation := extractPackageNameLocation(block, name, pkgRef.Line.Start, f.Path())
		versionLocation := extractPackageVersionLocation(block, pkgRef.Line.Start, f.Path())

		pkg := lockfile.PackageDetails{
			Name:            name,
			Version:         version,
			PackageManager:  nugetPackageManager,
			Ecosystem:       models.EcosystemNuGet,
			IsDirect:        true, // .csproj only contains direct dependencies
			DepGroups:       []string{string(depGroup)},
			BlockLocation:   blockLocation,
			NameLocation:    nameLocation,
			VersionLocation: versionLocation,
		}

		details = append(details, pkg)
	}

	return details, nil
}

// GetInclude returns the Include value from a PackageReference
func GetInclude(pr PackageReference) string {
	if pr.Include != nil {
		return *pr.Include
	}
	if pr.IncludeAttr != nil {
		return *pr.IncludeAttr
	}

	return ""
}

// GetVersion returns the Version value from a PackageReference with property substitution applied
func GetVersion(pr PackageReference, properties map[string]string) string {
	var version string
	if pr.Version != nil {
		version = *pr.Version
	} else if pr.VersionAttr != nil {
		version = *pr.VersionAttr
	} else {
		return ""
	}

	// Substitute version from properties if available
	_, exists := extractNugetVariable(version)
	if exists && len(properties) > 0 {
		version = substituteProperties(version, properties)
	}

	return version
}

// IsDevDependency checks if a PackageReference is a dev dependency (PrivateAssets="all")
func IsDevDependency(pr PackageReference) bool {
	return (pr.PrivateAssetsAttr != nil && strings.Contains(strings.ToLower(*pr.PrivateAssetsAttr), "all")) ||
		(pr.PrivateAssets != nil && strings.Contains(strings.ToLower(*pr.PrivateAssets), "all"))
}

// buildPropertyMap creates a map of property names to their values from PropertyGroup elements
func buildPropertyMap(propertyGroups []PropertyGroup) map[string]string {
	properties := make(map[string]string)
	for _, group := range propertyGroups {
		for _, prop := range group.Properties {
			properties[prop.XMLName.Local] = prop.Value
		}
	}

	return properties
}

// substituteProperties replaces property references like $(PropertyName) with their actual values
// It handles nested references by iterating until no more substitutions are possible
func substituteProperties(value string, properties map[string]string) string {
	limit := 10
	newValue := value

	for range limit {
		variable, isVariable := extractNugetVariable(newValue)
		if !isVariable {
			// Property isn't a variable
			break
		}

		substitute, substituteExists := properties[variable]
		if !substituteExists {
			// We cannot find a substitute to the variable
			break
		}

		newValue = substitute
	}

	return newValue
}

// extractPackageNameLocation extracts the file position of a package name from a block of lines
func extractPackageNameLocation(block []string, packageName string, lineStart int, filename string) *models.FilePosition {
	nameLocation := fileposition.ExtractStringPositionInBlock(block, packageName, lineStart)
	if nameLocation != nil {
		nameLocation.Filename = filename
	}

	return nameLocation
}

// extractPackageVersionLocation extracts the file position of a package version from a block of lines
func extractPackageVersionLocation(block []string, lineStart int, filename string) *models.FilePosition {
	versionLocation := fileposition.ExtractDelimitedRegexpPositionInBlock(block, "[^\"]*", lineStart, "Version=\"", "\"")
	if versionLocation == nil {
		versionLocation = fileposition.ExtractDelimitedRegexpPositionInBlock(block, "[^<]*", lineStart, "<Version>", "</")
	}
	if versionLocation != nil {
		versionLocation.Filename = filename
	}

	return versionLocation
}

// Matches strings like: "$(PropertyName)" and extract "PropertyName"
var variableRegexp = cachedregexp.MustCompile(`^\$\((.*)\)$`)

func extractNugetVariable(value string) (string, bool) {
	matches := variableRegexp.FindStringSubmatch(value)
	if len(matches) == 2 {
		return matches[1], true
	}

	return "", false
}

var _ lockfile.Extractor = NuGetCsprojExtractor{}

// traverseAndMergePropsFiles discovers .props files recursively and merges their properties
// in a single pass to avoid reading the same file multiple times.
// Returns merged properties with correct precedence order.
func traverseAndMergePropsFiles(csprojPath string, csprojImports []Import, localProperties map[string]string) map[string]string {
	allProperties := make(map[string]string)
	processedFiles := make(map[string]bool)
	csprojDir := filepath.Dir(csprojPath)

	// Process convention-based files first (Directory.Build.props has the lowest priority)
	conventionFiles := []string{buildPropsFile, packagesPropsFile}
	for _, fileName := range conventionFiles {
		if path, exists := findFileInParentDirs(csprojDir, fileName); exists {
			propsFileProperties := processPropsFile(path, processedFiles)

			// Merge new properties with all properties
			for key, value := range propsFileProperties {
				allProperties[key] = value
			}
		}
	}

	// Process explicit imports from .csproj (have precedence over the default Build/Packages files)
	importProperties := readPropertiesFromPropsFilesImports(csprojImports, csprojDir, processedFiles)
	for key, value := range importProperties {
		allProperties[key] = value
	}

	// Finally, use local properties from .csproj which have the highest priority
	for key, value := range localProperties {
		allProperties[key] = value
	}

	return allProperties
}

// processPropsFile recursively processes a .props file and returns its properties
// Returns a map containing properties from this file and all its imports
func processPropsFile(propsPath string, processedFiles map[string]bool) map[string]string {
	// Skip if already processed
	if processedFiles[propsPath] {
		return make(map[string]string)
	}
	processedFiles[propsPath] = true

	// Parse the .props file
	content, err := os.ReadFile(propsPath)
	if err != nil {
		return make(map[string]string)
	}
	var propsFile PropsFile
	if err := xml.Unmarshal(content, &propsFile); err != nil {
		return make(map[string]string)
	}

	// Accumulate properties from nested imports
	properties := make(map[string]string)

	// First, recursively process any imports in this .props file
	propsFileDir := filepath.Dir(propsPath)
	importProperties := readPropertiesFromPropsFilesImports(propsFile.Imports, propsFileDir, processedFiles)
	for key, value := range importProperties {
		properties[key] = value
	}

	// Then merge properties from this file (later imports override earlier ones)
	fileProperties := buildPropertyMap(propsFile.PropertyGroups)
	for key, value := range fileProperties {
		properties[key] = value
	}

	return properties
}

// readPropertiesFromPropsFilesImports processes a list of imports and merges their properties
// Returns a map of all properties found in the imports
func readPropertiesFromPropsFilesImports(imports []Import, baseDir string, processedFiles map[string]bool) map[string]string {
	allProperties := make(map[string]string)

	for _, imp := range imports {
		if !isPropsFile(imp.Project) {
			continue
		}

		// Make sure to standardize the path separator. We could find both `\` or `/` in the import path.
		importPath := strings.ReplaceAll(imp.Project, "\\", string(os.PathSeparator))

		if !filepath.IsAbs(importPath) {
			importPath = filepath.Clean(filepath.Join(baseDir, importPath))
		}

		if _, err := os.Stat(importPath); err == nil {
			propsFileProperties := processPropsFile(importPath, processedFiles)
			for key, value := range propsFileProperties {
				allProperties[key] = value
			}
		}
	}

	return allProperties
}

// findFileInParentDirs searches for a file by walking up the directory tree
func findFileInParentDirs(startDir string, fileName string) (string, bool) {
	currentDir := startDir

	for {
		testPath := filepath.Join(currentDir, fileName)
		if _, err := os.Stat(testPath); err == nil {
			absPath, err := filepath.Abs(testPath)
			if err != nil {
				return testPath, true
			}

			return absPath, true
		}

		// Move to parent directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// Reached root directory
			break
		}
		currentDir = parentDir
	}

	return "", false
}

func isPropsFile(path string) bool {
	return strings.HasSuffix(path, propsFileSuffix)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.NuGetCsProjFilePath, NuGetCsprojExtractor{})
}

func ParseNuGetCsproj(pathToCsproj string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToCsproj, NuGetCsprojExtractor{})
}
