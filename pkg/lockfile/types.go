package lockfile

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type PackageDetails struct {
	Source          models.SourceInfo
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	TargetVersions  []string              `json:"targetVersions,omitempty"`
	Commit          string                `json:"commit,omitempty"`
	PURL            string                `json:"purl,omitempty"`
	Ecosystem       models.Ecosystem      `json:"ecosystem,omitempty"`
	DepGroups       []string              `json:"depGroups,omitempty"`
	BlockLocation   models.FilePosition   `json:"blockLocation,omitempty"`
	VersionLocation *models.FilePosition  `json:"versionLocation,omitempty"`
	NameLocation    *models.FilePosition  `json:"nameLocation,omitempty"`
	PackageManager  models.PackageManager `json:"packageManager,omitempty"`
	IsDirect        bool                  `json:"isDirect,omitempty"`
	Dependencies    []*PackageDetails     `json:"dependencies,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

func (pkg PackageDetails) IsVersionEmpty() bool {
	return pkg.Version == ""
}
