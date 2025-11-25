package lockfile

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	nugetCsprojFilePath = models.NuGetCsProjFilePath
)

type NugetCsProj struct {
	XMLName        xml.Name        `xml:"Project"`
	ItemGroups     []ItemGroup     `xml:"ItemGroup"`
	PropertyGroups []PropertyGroup `xml:"PropertyGroup"`
}

type ItemGroup struct {
	XMLName           xml.Name           `xml:"ItemGroup"`
	PackageReferences []PackageReference `xml:"PackageReference"`
}

type PropertyGroup struct {
	XMLName    xml.Name
	Properties []Property `xml:",any"`
}

type Property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type PackageReference struct {
	XMLName           xml.Name `xml:"PackageReference"`
	IncludeAttr       *string  `xml:"Include,attr"`
	Include           *string  `xml:"Include"`
	VersionAttr       *string  `xml:"Version,attr"`
	Version           *string  `xml:"Version"`
	PrivateAssetsAttr *string  `xml:"PrivateAssets,attr"`
	PrivateAssets     *string  `xml:"PrivateAssets"`
	models.FilePosition
}

type ParsedCsProj struct {
	PackagesByName   map[string]PackageReference
	PropertiesByName map[string]string
}

func (e NuGetCsprojExtractor) ShouldExtract(path string) bool {
	if !strings.HasSuffix(path, nugetCsprojFilePath) {
		return false
	}

	// Only use csproj extractor if packages.lock.json doesn't exist
	// This makes csproj a fallback when the lock file is not available
	dir := filepath.Dir(path)
	lockfilePath := filepath.Join(dir, nugetLockFilePath)

	if _, err := os.Stat(lockfilePath); err == nil {
		// Lock file exists, don't use csproj extractor
		return false
	}

	return true
}

// UnmarshalXML implements xml.Unmarshaler to capture line and column positions for each PackageReference.
// This custom unmarshaler is necessary because the standard xml.Unmarshal doesn't provide file position
// information. By manually iterating through XML tokens and calling decoder.InputPos(), we can record
// where each PackageReference appears in the file.
func (itemGroup *ItemGroup) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
DecodingLoop:
	for {
		lineStart, columnStart := decoder.InputPos()
		token, err := decoder.Token()
		if err != nil {
			return err
		}

		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local != "PackageReference" {
				continue
			}

			packageReference := PackageReference{}
			packageReference.SetLineStart(lineStart)
			packageReference.SetColumnStart(columnStart)

			err := decoder.DecodeElement(&packageReference, &elem)
			if err != nil {
				return err
			}

			lineEnd, columnEnd := decoder.InputPos()
			packageReference.SetLineEnd(lineEnd)
			packageReference.SetColumnEnd(columnEnd)
			itemGroup.PackageReferences = append(itemGroup.PackageReferences, packageReference)

		case xml.EndElement:
			if elem.Name == start.Name {
				break DecodingLoop
			}
		}
	}

	return nil
}

// ParseNugetCsProj parses a .csproj file and returns a map of package references by package name.
// This is shared logic used by both the extractor and matcher.
func ParseNugetCsProj(content []byte) (*ParsedCsProj, error) {
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

	// Build property map from PropertyGroups
	properties := buildPropertyMap(project.PropertyGroups)

	return &ParsedCsProj{
		PackagesByName:   packageReferenceByInclude,
		PropertiesByName: properties,
	}, nil
}

type NuGetCsprojExtractor struct{}

func (e NuGetCsprojExtractor) IsOfficiallySupported() bool {
	return nugetOfficiallySupported
}

func (e NuGetCsprojExtractor) PackageManager() models.PackageManager {
	return nugetPackageManager
}

func (e NuGetCsprojExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	parsedCsProj, err := ParseNugetCsProj(content)
	if err != nil {
		return nil, fmt.Errorf("could not parse csproj %s: %w", f.Path(), err)
	}
	packageReferences := parsedCsProj.PackagesByName
	fileProperties := parsedCsProj.PropertiesByName

	lines := fileposition.BytesToLines(content)
	details := make([]PackageDetails, 0, len(packageReferences))

	for name, pkgRef := range packageReferences {
		version := GetVersion(pkgRef, fileProperties)
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

		pkg := PackageDetails{
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

	for i := 0; i < limit; i++ {
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

var _ Extractor = NuGetCsprojExtractor{}

//nolint:gochecknoinits
func init() {
	registerExtractor(models.NugetCsProjFile, NuGetCsprojExtractor{})
}

func ParseNuGetCsproj(pathToCsproj string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToCsproj, NuGetCsprojExtractor{})
}
