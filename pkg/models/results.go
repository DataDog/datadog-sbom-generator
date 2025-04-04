package models

// Combined vulnerabilities found for the scanned packages
type VulnerabilityResults struct {
	Results                    []PackageSource            `json:"results"`
	Artifacts                  []ScannedArtifact          `json:"artifacts,omitempty"`
	ExperimentalAnalysisConfig ExperimentalAnalysisConfig `json:"experimental_config"`
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

// ExperimentalAnalysisConfig is an experimental type intended to contain the
// types of analysis performed on packages found by the scanner.
type ExperimentalAnalysisConfig struct {
	Licenses ExperimentalLicenseConfig `json:"licenses"`
}

type ExperimentalLicenseConfig struct {
	Summary   bool      `json:"summary"`
	Allowlist []License `json:"allowlist"`
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
	Package           PackageInfo        `json:"package"`
	DepGroups         []string           `json:"dependency_groups,omitempty"`
	Locations         []PackageLocations `json:"locations,omitempty"`
	Vulnerabilities   []Vulnerability    `json:"vulnerabilities,omitempty"`
	Groups            []GroupInfo        `json:"groups,omitempty"`
	Licenses          []License          `json:"licenses,omitempty"`
	LicenseViolations []License          `json:"license_violations,omitempty"`
	Metadata          PackageMetadata    `json:"metadata,omitempty"`
}

type GroupInfo struct {
	// IDs expected to be sorted in alphanumeric order
	IDs []string `json:"ids"`
	// Aliases include all aliases and IDs
	Aliases []string `json:"aliases"`
	// Map of Vulnerability IDs to AnalysisInfo
	ExperimentalAnalysis map[string]AnalysisInfo `json:"experimentalAnalysis,omitempty"`
	MaxSeverity          string                  `json:"max_severity"`
}

// IsCalled returns true if any analysis performed determines that the vulnerability is being called
// Also returns true if no analysis is performed
func (groupInfo *GroupInfo) IsCalled() bool {
	if len(groupInfo.IDs) == 0 {
		// This PackageVulns may be a license violation, not a
		// vulnerability.
		return false
	}

	if len(groupInfo.ExperimentalAnalysis) == 0 {
		return true
	}

	for _, analysis := range groupInfo.ExperimentalAnalysis {
		if analysis.Called {
			return true
		}
	}

	return false
}

func (groupInfo *GroupInfo) IndexString() string {
	// Assumes IDs is sorted
	return strings.Join(groupInfo.IDs, ",")
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
