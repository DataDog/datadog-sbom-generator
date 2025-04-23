package lockfile

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]models.PackageDetails, error)
