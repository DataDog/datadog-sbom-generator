package models

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results   []PackageSource   `json:"results"`
	Artifacts []ScannedArtifact `json:"artifacts,omitempty"`
}

type ArtifactDetail struct {
	Name      string
	Version   string
	Filename  string
	Ecosystem Ecosystem
}

type ScannedArtifact struct {
	ArtifactDetail
	DependsOn *ArtifactDetail
}

type SourceInfo struct {
	Path string `json:"path"`
}

type Metadata struct {
	RepoURL   string   `json:"repo_url"`
	DepGroups []string `json:"-"`
}

func (s SourceInfo) String() string {
	return s.Path
}

// Vulnerabilities grouped by sources
type PackageSource struct {
	Source   SourceInfo     `json:"source"`
	Packages []PackageVulns `json:"packages"`
}

// License is an SPDX license.
type License string

// Vulnerabilities grouped by package
// TODO: rename this to be Package as it now includes license information too.
type PackageVulns struct {
	Package         PackageInfo        `json:"package"`
	DepGroups       []string           `json:"dependency_groups,omitempty"`
	Locations       []PackageLocations `json:"locations,omitempty"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities,omitempty"`
	Metadata        PackageMetadata    `json:"metadata,omitempty"`
}

type AnalysisInfo struct {
	Called bool `json:"called"`
}

// Specific package information
type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Commit    string `json:"commit,omitempty"`
}
