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
	var csProj NugetCsProj
	err := xml.Unmarshal(content, &csProj)
	if err != nil {
		return nil, err
	}

	// We index by condition, as a given package can be declared multiple times
	// with different versions based on conditions (like targetFramework).
	packagesByConditionAndName := make(map[string]map[string]PackageReference)
	for _, itemGroup := range csProj.ItemGroups {
		conditionKey := getConditionKey(itemGroup.ConditionAttr)

		// Initialize the inner map if it doesn't exist
		if packagesByConditionAndName[conditionKey] == nil {
			packagesByConditionAndName[conditionKey] = make(map[string]PackageReference)
		}

		for _, packageReference := range itemGroup.PackageReferences {
			include := GetInclude(packageReference)
			if include != "" {
				packagesByConditionAndName[conditionKey][include] = packageReference
			}
		}
	}

	// Discover and parse .props files recursively, merging properties and collecting PackageVersions
	propsData := extractProperties(csprojPath, csProj)

	return &ParsedCsProj{
		PackagesByConditionAndName: packagesByConditionAndName,
		MSBuildProperties:          propsData,
	}, nil
}

func (e NuGetCsprojExtractor) IsOfficiallySupported() bool {
	return nugetOfficiallySupported
}

func (e NuGetCsprojExtractor) PackageManager() models.PackageManager {
	return nugetPackageManager
}

func (e NuGetCsprojExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	parsedCsProj, err := ParseNugetCsProj(content, f.Path())
	if err != nil {
		return nil, fmt.Errorf("could not parse csproj %s: %w", f.Path(), err)
	}

	lines := fileposition.BytesToLines(content)
	details := make([]lockfile.PackageDetails, 0)

	// Iterate over all conditions and their packages
	for _, packagesByName := range parsedCsProj.PackagesByConditionAndName {
		for name, pkgRef := range packagesByName {
			versions := GetVersions(pkgRef, parsedCsProj.MSBuildProperties)
			if len(versions) == 0 {
				// Skip packages without versions - they couldn't be resolved
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

			for _, version := range versions {
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
		}
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

// GetVersions returns the Versions from a PackageReference with property substitution applied
// If no version is found in the PackageReference, it looks up the version from PackageVersions (central package management)
// A package can have multiple versions depending on the targetFramework used to build the application.
func GetVersions(pr PackageReference, properties ParsedProperties) []string {
	versions := make([]string, 0)
	if pr.Version != nil {
		versions = append(versions, *pr.Version)
	} else if pr.VersionAttr != nil {
		versions = append(versions, *pr.VersionAttr)
	} else if properties.ManagePackageVersionsCentrally {
		packageName := GetInclude(pr)
		if versionsInfo, exists := properties.VersionsByPackageName[packageName]; exists {
			for _, versionInfo := range versionsInfo {
				versions = append(versions, versionInfo.Version)
			}
		}
	}

	for index, version := range versions {
		// Substitute version from properties if the version was a variable
		_, exists := extractNugetVariable(version)
		if exists && len(properties.PropertiesByName) > 0 {
			versions[index] = substituteProperties(version, properties.PropertiesByName)
		}
	}

	return versions
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

// getConditionKey returns the condition string or empty string if nil
func getConditionKey(condition *string) string {
	if condition != nil {
		return *condition
	}

	return ""
}

var _ lockfile.Extractor = NuGetCsprojExtractor{}

// extractProperties discovers .props files recursively and merges their properties
// in a single pass to avoid reading the same file multiple times.
// Returns ParsedProperties with merged properties, package versions, and whether central package management is enabled.
func extractProperties(csprojPath string, csproj NugetCsProj) ParsedProperties {
	result := newParsedProperties()

	processedFiles := make(map[string]bool)
	csprojDir := filepath.Dir(csprojPath)

	// Process convention-based files first (Directory.Build.props has the lowest priority)
	conventionFiles := []string{buildPropsFile, packagesPropsFile}
	for _, fileName := range conventionFiles {
		if path, exists := findFileInParentDirs(csprojDir, fileName); exists {
			propsFileData := processPropsFile(path, processedFiles)

			// Merge properties
			for key, value := range propsFileData.PropertiesByName {
				result.PropertiesByName[key] = value
			}

			// Merge package versions
			for pkgName, versions := range propsFileData.VersionsByPackageName {
				result.VersionsByPackageName[pkgName] = append(result.VersionsByPackageName[pkgName], versions...)
			}
		}
	}

	// Process explicit imports (have precedence over the default Build/Packages files)
	importedProps := readPropertiesFromPropsFilesImports(csproj.Imports, csprojDir, processedFiles)
	for key, value := range importedProps.PropertiesByName {
		result.PropertiesByName[key] = value
	}

	// Merge package versions from imports
	for pkgName, versions := range importedProps.VersionsByPackageName {
		result.VersionsByPackageName[pkgName] = append(result.VersionsByPackageName[pkgName], versions...)
	}

	// Finally, use local properties from .csproj which have the highest priority
	localProperties := buildPropertyMap(csproj.PropertyGroups)
	for key, value := range localProperties {
		result.PropertiesByName[key] = value
	}

	// Check if central package management is enabled by looking at the merged properties
	if managedValue, exists := result.PropertiesByName["ManagePackageVersionsCentrally"]; exists {
		result.ManagePackageVersionsCentrally = strings.EqualFold(managedValue, "true")
	}

	return result
}

// processPropsFile recursively processes a .props file and returns its properties and package versions
// Returns a ParsedProperties containing properties and package versions from this file and all its imports
func processPropsFile(propsPath string, processedFiles map[string]bool) ParsedProperties {
	// Skip if already processed
	if processedFiles[propsPath] {
		return newParsedProperties()
	}
	processedFiles[propsPath] = true

	// Parse the .props file
	content, err := os.ReadFile(propsPath)
	if err != nil {
		return newParsedProperties()
	}
	var propsFile PropsFile
	if err := xml.Unmarshal(content, &propsFile); err != nil {
		return newParsedProperties()
	}

	result := newParsedProperties()

	// First, recursively process any imports in this .props file
	propsFileDir := filepath.Dir(propsPath)
	importedProps := readPropertiesFromPropsFilesImports(propsFile.Imports, propsFileDir, processedFiles)
	for key, value := range importedProps.PropertiesByName {
		result.PropertiesByName[key] = value
	}
	for pkgName, versions := range importedProps.VersionsByPackageName {
		result.VersionsByPackageName[pkgName] = append(result.VersionsByPackageName[pkgName], versions...)
	}

	// Then merge properties from this file (later imports override earlier ones)
	fileProperties := buildPropertyMap(propsFile.PropertyGroups)
	for key, value := range fileProperties {
		result.PropertiesByName[key] = value
	}

	// Extract PackageVersion entries from ItemGroups and convert to PackageVersionInfo
	for _, itemGroup := range propsFile.ItemGroups {
		for _, pkgVersion := range itemGroup.PackageVersions {
			info := convertToPackageVersionInfo(pkgVersion)
			if info.Name != "" {
				result.VersionsByPackageName[info.Name] = append(result.VersionsByPackageName[info.Name], info)
			}
		}
	}

	return result
}

// readPropertiesFromPropsFilesImports processes a list of imports and merges their properties and package versions
// Returns a ParsedProperties with all properties and package versions found in the imports
func readPropertiesFromPropsFilesImports(imports []Import, baseDir string, processedFiles map[string]bool) ParsedProperties {
	result := newParsedProperties()

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
			propsFileData := processPropsFile(importPath, processedFiles)
			for key, value := range propsFileData.PropertiesByName {
				result.PropertiesByName[key] = value
			}
			for pkgName, versions := range propsFileData.VersionsByPackageName {
				result.VersionsByPackageName[pkgName] = append(result.VersionsByPackageName[pkgName], versions...)
			}
		}
	}

	return result
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

// convertToPackageVersionInfo converts a PackageVersion XML element to a simplified PackageVersionInfo
func convertToPackageVersionInfo(pv PackageVersion) PackageVersionInfo {
	info := PackageVersionInfo{}

	// Extract name
	if pv.Include != nil {
		info.Name = *pv.Include
	} else if pv.IncludeAttr != nil {
		info.Name = *pv.IncludeAttr
	}

	// Extract version
	if pv.Version != nil {
		info.Version = *pv.Version
	} else if pv.VersionAttr != nil {
		info.Version = *pv.VersionAttr
	}

	// Extract condition (optional)
	if pv.ConditionAttr != nil {
		info.Condition = *pv.ConditionAttr
	}

	return info
}

func newParsedProperties() ParsedProperties {
	return ParsedProperties{
		PropertiesByName:      make(map[string]string),
		VersionsByPackageName: make(map[string][]PackageVersionInfo),
	}
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
