package models

type PackageDetails struct {
	Source                SourceInfo
	Name                  string            `json:"name"`
	Version               string            `json:"version"`
	TargetVersions        []string          `json:"targetVersions,omitempty"`
	Commit                string            `json:"commit,omitempty"`
	PURL                  string            `json:"purl,omitempty"`
	Ecosystem             Ecosystem         `json:"ecosystem,omitempty"`
	DepGroups             []string          `json:"depGroups,omitempty"`
	LockfileBlockLocation FilePosition      `json:"lockfileBlockLocation,omitempty"`
	BlockLocation         FilePosition      `json:"blockLocation,omitempty"`
	VersionLocation       *FilePosition     `json:"versionLocation,omitempty"`
	NameLocation          *FilePosition     `json:"nameLocation,omitempty"`
	PackageManager        PackageManager    `json:"packageManager,omitempty"`
	IsDirect              bool              `json:"isDirect,omitempty"`
	Dependencies          []*PackageDetails `json:"dependencies,omitempty"`
}

func (pkg PackageDetails) IsVersionEmpty() bool {
	return pkg.Version == ""
}
