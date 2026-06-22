package dotnet

import (
	"encoding/xml"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	nugetPackageManager      = models.NuGet
	nugetOfficiallySupported = true
)

// ============================================================================
// Dependency Type Constants
// ============================================================================

const (
	projectDependencyType string = "Project"
	propsFileSuffix       string = ".props"
	buildPropsFile        string = "Directory.Build.props"
	packagesPropsFile     string = "Directory.Packages.props"
)

// ============================================================================
// NuGet .csproj Types
// ============================================================================

type NugetCsProj struct {
	XMLName        xml.Name        `xml:"Project"`
	ItemGroups     []ItemGroup     `xml:"ItemGroup"`
	PropertyGroups []PropertyGroup `xml:"PropertyGroup"`
	Imports        []Import        `xml:"Import"`
}

type PropsFile struct {
	XMLName        xml.Name        `xml:"Project"`
	ItemGroups     []ItemGroup     `xml:"ItemGroup"`
	PropertyGroups []PropertyGroup `xml:"PropertyGroup"`
	Imports        []Import        `xml:"Import"`
}

type ItemGroup struct {
	XMLName           xml.Name           `xml:"ItemGroup"`
	PackageReferences []PackageReference `xml:"PackageReference"`
	PackageVersions   []PackageVersion   `xml:"PackageVersion"`
	ProjectReferences []ProjectReference `xml:"ProjectReference"`
	ConditionAttr     *string            `xml:"Condition,attr"`
}

type ProjectReference struct {
	XMLName     xml.Name `xml:"ProjectReference"`
	IncludeAttr *string  `xml:"Include,attr"`
}

type Import struct {
	XMLName   xml.Name `xml:"Import"`
	Project   string   `xml:"Project,attr"`
	Condition string   `xml:"Condition,attr"`
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
	XMLName             xml.Name `xml:"PackageReference"`
	IncludeAttr         *string  `xml:"Include,attr"`
	Include             *string  `xml:"Include"`
	VersionAttr         *string  `xml:"Version,attr"`
	Version             *string  `xml:"Version"`
	VersionOverrideAttr *string  `xml:"VersionOverride,attr"`
	VersionOverride     *string  `xml:"VersionOverride"`
	PrivateAssetsAttr   *string  `xml:"PrivateAssets,attr"`
	PrivateAssets       *string  `xml:"PrivateAssets"`
	models.FilePosition
}

type PackageVersion struct {
	XMLName       xml.Name `xml:"PackageVersion"`
	IncludeAttr   *string  `xml:"Include,attr"`
	Include       *string  `xml:"Include"`
	VersionAttr   *string  `xml:"Version,attr"`
	Version       *string  `xml:"Version"`
	ConditionAttr *string  `xml:"Condition,attr"`
	models.FilePosition
}

// PackageVersionInfo is a simplified representation of a package version for central package management
type PackageVersionInfo struct {
	Name      string
	Version   string
	Condition string // Optional condition (e.g., "'$(TargetFramework)' == 'net6.0'")
}

type ParsedCsProj struct {
	PackagesByConditionAndName map[string]map[string]PackageReference // map[condition]map[packageName]PackageReference
	MSBuildProperties          ParsedMSBuildProperties
}

type ParsedMSBuildProperties struct {
	PropertiesByName               map[string]string
	VersionsByPackageName          map[string][]PackageVersionInfo
	ManagePackageVersionsCentrally bool
}

type NuGetCsprojExtractor struct{}

// ============================================================================
// NuGet packages.lock.json Types
// ============================================================================

type NuGetLockPackage struct {
	Resolved string `json:"resolved"`
	Type     string `json:"type"`
}

// NuGetLockfile contains the required dependency information as defined in
// https://github.com/NuGet/NuGet.Client/blob/6.5.0.136/src/NuGet.Core/NuGet.ProjectModel/ProjectLockFile/PackagesLockFileFormat.cs
type NuGetLockfile struct {
	Version      int                                    `json:"version"`
	Dependencies map[string]map[string]NuGetLockPackage `json:"dependencies"`
}

type NuGetLockExtractor struct {
	extractor.WithMatcher
}

// ============================================================================
// Matcher Types
// ============================================================================

type NugetCsprojMatcher struct{}

// packageKey tracks name+version combinations to merge target frameworks
type packageKey struct {
	name    string
	version string
}
