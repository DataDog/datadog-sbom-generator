package sbom

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

const (
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

const (
	libraryComponentType = "library"
	fileComponentType    = "file"
)

var SeverityMapper = map[models.SeverityType]cyclonedx.ScoringMethod{
	models.SeverityCVSSV2: cyclonedx.ScoringMethodCVSSv2,
	models.SeverityCVSSV3: cyclonedx.ScoringMethodCVSSv3,
	models.SeverityCVSSV4: cyclonedx.ScoringMethodCVSSv4,
}
