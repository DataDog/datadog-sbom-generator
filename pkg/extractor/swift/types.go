package swift

import "github.com/DataDog/datadog-sbom-generator/pkg/models"

const (
	swiftPackageManager      = models.SwiftPM
	swiftFilePath            = models.SwiftFilePath
	swiftOfficiallySupported = true
)

// packageResolvedFile is the top-level JSON structure that works for all versions.
// For v1, pins are nested under "object"; for v2/v3 they are at the top level.
type packageResolvedFile struct {
	Version int                    `json:"version"`
	Object  *packageResolvedObject `json:"object,omitempty"` // v1 only
	Pins    []packageResolvedPin   `json:"pins,omitempty"`   // v2/v3
}

// packageResolvedObject wraps pins in v1 format.
type packageResolvedObject struct {
	Pins []packageResolvedPinV1 `json:"pins"`
}

// packageResolvedPinV1 represents a pin in v1 format.
type packageResolvedPinV1 struct {
	Package       string               `json:"package"`
	RepositoryURL string               `json:"repositoryURL"`
	State         packageResolvedState `json:"state"`
}

// packageResolvedPin represents a pin in v2/v3 format.
type packageResolvedPin struct {
	Identity string               `json:"identity"`
	Kind     string               `json:"kind"`
	Location string               `json:"location"`
	State    packageResolvedState `json:"state"`
}

// packageResolvedState holds the version/revision/branch for a pin.
type packageResolvedState struct {
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
	Branch   string `json:"branch,omitempty"`
}
