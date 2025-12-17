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
	"github.com/DataDog/datadog-sbom-generator/internal/utility/sliceutil"
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
// rootDir is optional - if provided, limits parent directory traversal to this directory
func ParseNugetCsProj(content []byte, csprojPath string, rootDir string) (*ParsedCsProj, error) {
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
	propsData := extractBuildPropertiesFromCsproj(csprojPath, csProj, rootDir)

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

	parsedCsProj, err := ParseNugetCsProj(content, f.Path(), context.RootDir)
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
func GetVersions(pr PackageReference, buildProperties ParsedMSBuildProperties) []string {
	versions := make([]string, 0)
	versionCandidates := []*string{
		pr.VersionOverride,
		pr.VersionOverrideAttr,
		pr.Version,
		pr.VersionAttr,
	}

	for _, v := range versionCandidates {
		if v != nil {
			versions = append(versions, *v)
			break // we keep the first match
		}
	}

	// Fallback to centralized versions
	if len(versions) == 0 && buildProperties.ManagePackageVersionsCentrally {
		packageName := GetInclude(pr)
		if versionsInfo, exists := buildProperties.VersionsByPackageName[packageName]; exists {
			for _, versionInfo := range versionsInfo {
				versions = append(versions, versionInfo.Version)
			}
		}
	}

	for index, version := range versions {
		// Substitute version from properties if the version was a variable
		_, exists := extractNugetVariable(version)
		if exists && len(buildProperties.PropertiesByName) > 0 {
			versions[index] = substituteProperties(version, buildProperties.PropertiesByName)
		}
	}

	return versions
}

// IsDevDependency checks if a PackageReference is a dev dependency (PrivateAssets="all")
func IsDevDependency(pr PackageReference) bool {
	return (pr.PrivateAssetsAttr != nil && strings.Contains(strings.ToLower(*pr.PrivateAssetsAttr), "all")) ||
		(pr.PrivateAssets != nil && strings.Contains(strings.ToLower(*pr.PrivateAssets), "all"))
}

// merge merges another ParsedMSBuildProperties into this one
func (p *ParsedMSBuildProperties) merge(other ParsedMSBuildProperties) {
	for key, value := range other.PropertiesByName {
		p.PropertiesByName[key] = value
	}
	for pkgName, versions := range other.VersionsByPackageName {
		p.VersionsByPackageName[pkgName] = append(p.VersionsByPackageName[pkgName], versions...)
	}
}

// mergeProperties merges properties from a map into this ParsedMSBuildProperties
func (p *ParsedMSBuildProperties) mergeProperties(properties map[string]string) {
	for key, value := range properties {
		p.PropertiesByName[key] = value
	}
}

// addPackageVersions adds package versions from ItemGroups
func (p *ParsedMSBuildProperties) addPackageVersions(itemGroups []ItemGroup) {
	for _, itemGroup := range itemGroups {
		for _, pkgVersion := range itemGroup.PackageVersions {
			info := convertToPackageVersionInfo(pkgVersion)
			if info.Name != "" {
				p.VersionsByPackageName[info.Name] = append(p.VersionsByPackageName[info.Name], info)
			}
		}
	}
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

// extractBuildPropertiesFromCsproj discovers .props files recursively and merges their build properties
// in a single pass to avoid reading the same file multiple times.
// Returns ParsedMSBuildProperties with merged properties, package versions, and whether central package management is enabled.
// rootDir is optional - if provided, limits parent directory traversal to this directory
func extractBuildPropertiesFromCsproj(csprojPath string, csproj NugetCsProj, rootDir string) ParsedMSBuildProperties {
	result := newMSBuildProperties()

	processedFiles := make(map[string]bool)
	csprojDir := filepath.Dir(csprojPath)

	// Process convention-based files first (Directory.Build.props has the lowest priority)
	// Files are returned from furthest to nearest, so they are merged in the correct priority order
	conventionFiles := []string{buildPropsFile, packagesPropsFile}
	for _, fileName := range conventionFiles {
		paths := findFileInParentDirs(csprojDir, fileName, rootDir)
		for _, path := range paths {
			propsFileData := extractPropertiesFromPropsFile(path, processedFiles)
			result.merge(propsFileData)
		}
	}

	// Process explicit imports (have precedence over the default Build/Packages files)
	importedProps := extractPropertiesFromImports(csproj.Imports, csprojDir, processedFiles)
	result.merge(importedProps)

	// Finally, use local properties from .csproj which have the highest priority
	localProperties := buildPropertyMap(csproj.PropertyGroups)
	result.mergeProperties(localProperties)

	// Check if central package management is enabled by looking at the merged properties
	if managedValue, exists := result.PropertiesByName["ManagePackageVersionsCentrally"]; exists {
		result.ManagePackageVersionsCentrally = strings.EqualFold(managedValue, "true")
	}

	return result
}

// extractPropertiesFromPropsFile recursively processes a .props file and returns its properties and package versions
// Returns a ParsedMSBuildProperties containing properties and package versions from this file and all its imports
func extractPropertiesFromPropsFile(propsPath string, processedFiles map[string]bool) ParsedMSBuildProperties {
	// Skip if already processed
	if processedFiles[propsPath] {
		return newMSBuildProperties()
	}
	processedFiles[propsPath] = true

	// Parse the .props file
	content, err := os.ReadFile(propsPath)
	if err != nil {
		return newMSBuildProperties()
	}
	var propsFile PropsFile
	if err := xml.Unmarshal(content, &propsFile); err != nil {
		return newMSBuildProperties()
	}

	result := newMSBuildProperties()

	// First, recursively process any imports in this .props file
	propsFileDir := filepath.Dir(propsPath)
	importedProps := extractPropertiesFromImports(propsFile.Imports, propsFileDir, processedFiles)
	result.merge(importedProps)

	// Then merge properties from this file (later imports override earlier ones)
	fileProperties := buildPropertyMap(propsFile.PropertyGroups)
	result.mergeProperties(fileProperties)

	// Extract PackageVersion entries from ItemGroups
	result.addPackageVersions(propsFile.ItemGroups)

	return result
}

// extractPropertiesFromImports processes a list of imports and merges their properties and package versions
// Returns a ParsedMSBuildProperties with all properties and package versions found in the imports
func extractPropertiesFromImports(imports []Import, baseDir string, processedFiles map[string]bool) ParsedMSBuildProperties {
	result := newMSBuildProperties()

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
			propsFileData := extractPropertiesFromPropsFile(importPath, processedFiles)
			result.merge(propsFileData)
		}
	}

	return result
}

// findFileInParentDirs searches for a file by walking up the directory tree and returns ALL matches
// rootDir is optional - if provided (as absolute path), stops traversal at this directory
// Returns files in order from furthest (closest to rootDir) to nearest (closest to startDir)
func findFileInParentDirs(startDir string, fileName string, rootDir string) []string {
	var foundPaths []string
	currentDir := startDir

	for {
		// Check if we've reached the rootDir boundary before checking for the file
		reachedRootDir := false
		if rootDir != "" {
			absCurrentDir, err := filepath.Abs(currentDir)
			if err == nil && absCurrentDir == rootDir {
				reachedRootDir = true
			}
		}

		// Check if the file exists in the current directory
		testPath := filepath.Join(currentDir, fileName)
		if _, err := os.Stat(testPath); err == nil {
			absPath, err := filepath.Abs(testPath)
			if err != nil {
				foundPaths = append(foundPaths, testPath)
			} else {
				foundPaths = append(foundPaths, absPath)
			}
		}

		// Stop if we've reached the rootDir boundary
		if reachedRootDir {
			break
		}

		// Move to parent directory
		parentDir := filepath.Dir(currentDir)
		if parentDir == currentDir {
			// Reached filesystem root directory
			break
		}
		currentDir = parentDir
	}

	// Reverse the order so files closest to rootDir come first (lowest priority)
	// and files closest to startDir come last (highest priority)
	sliceutil.Reverse(foundPaths)

	return foundPaths
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

func newMSBuildProperties() ParsedMSBuildProperties {
	return ParsedMSBuildProperties{
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

func ParseNuGetCsprojWithContext(pathToCsproj string, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFileWithContext(pathToCsproj, NuGetCsprojExtractor{}, context)
}
