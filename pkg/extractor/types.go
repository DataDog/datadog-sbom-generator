package extractor

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type PackageDetails struct {
	Source                       models.SourceInfo
	Name                         string                `json:"name"`
	Version                      string                `json:"version"`
	VersionRange                 string                `json:"versionRange,omitempty"`
	TargetVersions               []string              `json:"targetVersions,omitempty"`
	TargetFrameworks             []string              `json:"targetFrameworks,omitempty"`
	Commit                       string                `json:"commit,omitempty"`
	PURL                         string                `json:"purl,omitempty"`
	Ecosystem                    models.Ecosystem      `json:"ecosystem,omitempty"`
	DepGroups                    []string              `json:"depGroups,omitempty"`
	BlockLocation                models.FilePosition   `json:"blockLocation,omitempty"`
	LocationRole                 string                `json:"locationRole,omitempty"`
	VersionLocation              *models.FilePosition  `json:"versionLocation,omitempty"`
	NameLocation                 *models.FilePosition  `json:"nameLocation,omitempty"`
	PackageManager               models.PackageManager `json:"packageManager,omitempty"`
	IsDirect                     bool                  `json:"isDirect,omitempty"`
	RequiresTransitiveEnrichment bool                  `json:"requiresTransitiveEnrichment,omitempty"`
	Opaque                       bool                  `json:"opaque,omitempty"`
	Dependencies                 []*PackageDetails     `json:"dependencies,omitempty"`
	Exclusions                   []string              `json:"exclusions,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

func (pkg PackageDetails) IsVersionEmpty() bool {
	return pkg.Version == ""
}
