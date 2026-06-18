package javascript

import (
	"encoding/json"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// NPM Constants
// ============================================================================

const (
	npmPackageManager      = models.NPM
	npmOfficiallySupported = true
	nodeModulesPath        = "node_modules/"
)

// ============================================================================
// NPM Types
// ============================================================================

type NpmLockDependency struct {
	// For an aliased package, Version is like "npm:[name]@[version]"
	Version      string                        `json:"version"`
	Dependencies map[string]*NpmLockDependency `json:"dependencies,omitempty"`

	Dev      bool `json:"dev,omitempty"`
	Optional bool `json:"optional,omitempty"`

	Requires map[string]string `json:"requires,omitempty"`

	models.FilePosition
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

type npmPackageDetailsMap map[string]extractor.PackageDetails

type NpmLockExtractor struct {
	extractor.WithMatcher
}

// ============================================================================
// Node Modules Constants
// ============================================================================

const (
	nodeModulesPackageManager      = models.NPM
	nodeModulesOfficiallySupported = false
)

// ============================================================================
// Node Modules Types
// ============================================================================

type NodeModulesExtractor struct{}

// ============================================================================
// PNPM Constants
// ============================================================================

const (
	pnpmPackageManager      = models.Pnpm
	pnpmOfficiallySupported = true
)

// ============================================================================
// PNPM v9 Types
// ============================================================================

type PnpmLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type PnpmLockDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type PnpmPackage struct {
	Resolution map[string]string `yaml:"resolution"`
	Version    string            `yaml:"version"`
}

type (
	PnpmLockPackages map[string]PnpmPackage
	PnpmDependencies map[string]PnpmLockDependency
)

type PnpmImporters struct {
	Dependencies         PnpmDependencies `yaml:"dependencies,omitempty"`
	OptionalDependencies PnpmDependencies `yaml:"optionalDependencies,omitempty"`
	DevDependencies      PnpmDependencies `yaml:"devDependencies,omitempty"`
}

type PnpmSnapshot struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

type PnpmLockfile struct {
	Version   string                   `yaml:"lockfileVersion"`
	Importers map[string]PnpmImporters `yaml:"importers,omitempty"`
	Packages  PnpmLockPackages         `yaml:"packages,omitempty"`
	Snapshots map[string]PnpmSnapshot  `yaml:"snapshots,omitempty"`
}

type PnpmDirectDependency struct {
	Pkg           extractor.PackageDetails
	Dep           PnpmLockDependency
	WorkspacePath string
}

// ============================================================================
// PNPM Legacy Types
// ============================================================================

type PnpmLegacyLockPackageResolution struct {
	Tarball string `yaml:"tarball"`
	Commit  string `yaml:"commit"`
	Repo    string `yaml:"repo"`
	Type    string `yaml:"type"`
}

type PnpmLegacyLockPackage struct {
	Resolution PnpmLegacyLockPackageResolution `yaml:"resolution"`
	Name       string                          `yaml:"name"`
	Version    string                          `yaml:"version"`
	Dev        bool                            `yaml:"dev"`
}

type PnpmLegacyLockDependency struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

type (
	PnpmLegacyLockPackages map[string]PnpmLegacyLockPackage
	PnpmLegacySpecifiers   map[string]string
	PnpmLegacyDependencies map[string]PnpmLegacyLockDependency
)

type PnpmLegacyLockfile struct {
	Version              string                 `yaml:"lockfileVersion"`
	Packages             PnpmLegacyLockPackages `yaml:"packages,omitempty"`
	Specifiers           PnpmLegacySpecifiers   `yaml:"specifiers,omitempty"`
	Dependencies         PnpmLegacyDependencies `yaml:"dependencies,omitempty"`
	OptionalDependencies PnpmLegacyDependencies `yaml:"optionalDependencies,omitempty"`
	DevDependencies      PnpmLegacyDependencies `yaml:"devDependencies,omitempty"`
}

type PnpmLockExtractor struct {
	extractor.WithMatcher
}

// ============================================================================
// Bun Constants
// ============================================================================

const (
	bunPackageManager      = models.Bun
	bunOfficiallySupported = true
)

// ============================================================================
// Bun Types
// ============================================================================

type BunLockfile struct {
	Version    int                          `json:"lockfileVersion"`
	Workspaces map[string]BunLockWorkspace  `json:"workspaces"`
	Packages   map[string][]json.RawMessage `json:"packages"`
}

type BunLockWorkspace struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type BunLockExtractor struct {
	extractor.WithMatcher
}

// ============================================================================
// Yarn Constants
// ============================================================================

const (
	yarnPackageManager            = models.Yarn
	yarnFilePath                  = models.YarnFilePath
	yarnOfficiallySupported       = true
	yarnLocalVersionMarker        = "-use.local"
	yarnWorkspaceResolutionMarker = "@workspace:"
	yarnWorkspaceVersionMarker    = "workspace:"
)

// ============================================================================
// Yarn Types
// ============================================================================

type YarnDependency struct {
	Name     string
	Version  string
	Registry string
}

type YarnPackage struct {
	Name          string
	Version       string
	TargetVersion string
	Resolution    string
	Dependencies  []YarnDependency
	WorkspacePath string
	BlockLocation models.FilePosition
}

type YarnLockExtractor struct {
	extractor.WithMatcher
}

// YarnBerryJSON represents the Yarn v4+ JSON lockfile format (version 9+)
type YarnBerryJSON struct {
	Metadata struct {
		Version int `json:"version"`
	} `json:"__metadata"`
	Entries map[string]YarnBerryEntry `json:"entries"`
}

type YarnBerryEntry struct {
	Checksum   string              `json:"checksum"`
	Resolution YarnBerryResolution `json:"resolution"`
}

type YarnBerryResolution struct {
	Resolution   string            `json:"resolution"`
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

// ============================================================================
// Package.json Matcher Constants
// ============================================================================

const (
	typeDependencies = iota
	typeDevDependencies
	typeOptionalDependencies
)

// ============================================================================
// Package.json Matcher Types
// ============================================================================

type PackageJSONMatcher struct {
	// Used to store the patterns for workspaces in a given root package.json
	WorkspacePatterns []string
}

type WorkspacePackageJSON struct {
	Workspaces []string `json:"workspaces"`
}

/*
packageJSONDependencyMap is here to have access to all extractor.MatcherDependencyMap methods and at the same time having
a different type to have a clear UnmarshallJSON method for the json decoder and avoid overlaps with other matchers.
*/
type packageJSONDependencyMap struct {
	extractor.MatcherDependencyMap
	reporter reporter.Reporter
}

type packageJSONFile struct {
	Dependencies         packageJSONDependencyMap `json:"dependencies"`
	DevDependencies      packageJSONDependencyMap `json:"devDependencies"`
	OptionalDependencies packageJSONDependencyMap `json:"optionalDependencies"`
}

// ============================================================================
// Package.json Extractor Constants
// ============================================================================

const (
	packageJSONPackageManager      = models.NPM
	packageJSONOfficiallySupported = false
)

// ============================================================================
// Package.json Extractor Types
// ============================================================================

type PackageJSONExtractor struct{}

// UnmarshalYAML is a custom unmarshaler for PnpmLegacyDependencies
func (pnpmDependencies *PnpmLegacyDependencies) UnmarshalYAML(value *yaml.Node) error {
	if *pnpmDependencies == nil {
		*pnpmDependencies = make(map[string]PnpmLegacyLockDependency)
	}

	for i := 0; i < len(value.Content); i += 2 {
		var pnpmLockDependency PnpmLegacyLockDependency

		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		// lockfileVersion 6.0
		if valueNode.Kind == yaml.MappingNode {
			if err := valueNode.Decode(&pnpmLockDependency); err != nil {
				return err
			}
		} else {
			pnpmLockDependency.Version = valueNode.Value
		}

		(*pnpmDependencies)[keyNode.Value] = pnpmLockDependency
	}

	return nil
}
