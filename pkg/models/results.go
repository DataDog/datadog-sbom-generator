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
	Package                   PackageDetails  `json:"package"`
	DepGroups                 []string        `json:"dependency_groups,omitempty"`
	Vulnerabilities           []Vulnerability `json:"vulnerabilities,omitempty"`
	Metadata                  PackageMetadata `json:"metadata,omitempty"`
	AdvisoriesForReachability []string        `json:"reachability_advisories,omitempty"`
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
	Purl      string `json:"purl,omitempty"`
}

func (details PackageVulns) ExtractPackageLocations() PackageLocations {
	packageLocations := PackageLocations{
		Block: PackageLocation{
			Filename:    details.Package.BlockLocation.Filename,
			LineStart:   details.Package.BlockLocation.Line.Start,
			LineEnd:     details.Package.BlockLocation.Line.End,
			ColumnStart: details.Package.BlockLocation.Column.Start,
			ColumnEnd:   details.Package.BlockLocation.Column.End,
		},
	}
	if details.Package.NameLocation != nil {
		packageLocations.Name = &PackageLocation{
			Filename:    details.Package.NameLocation.Filename,
			LineStart:   details.Package.NameLocation.Line.Start,
			LineEnd:     details.Package.NameLocation.Line.End,
			ColumnStart: details.Package.NameLocation.Column.Start,
			ColumnEnd:   details.Package.NameLocation.Column.End,
		}
	}
	if details.Package.VersionLocation != nil {
		packageLocations.Version = &PackageLocation{
			Filename:    details.Package.VersionLocation.Filename,
			LineStart:   details.Package.VersionLocation.Line.Start,
			LineEnd:     details.Package.VersionLocation.Line.End,
			ColumnStart: details.Package.VersionLocation.Column.Start,
			ColumnEnd:   details.Package.VersionLocation.Column.End,
		}
	}

	return packageLocations
}
