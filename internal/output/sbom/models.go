package sbom

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/CycloneDX/cyclonedx-go"
)

const (
	cycloneDx15Schema = "http://cyclonedx.org/schema/bom-1.5.schema.json"
)

const (
	datadogPrefix = "datadog"
)

const (
	libraryComponentType = "library"
	fileComponentType    = "file"
)

const (
	// mavenParentPomProperty is a CycloneDX component property that records the
	// path of the parent POM for a Maven file-type component. It unambiguously
	// identifies the <parent> relationship, as opposed to ordinary module
	// dependencies that also appear in the bom.Dependencies section.
	mavenParentPomProperty = "datadog:maven-parent-pom"

	// mavenPackageProperty is a CycloneDX component property that records the
	// package URL for a Maven file-type component.
	mavenPackageProperty = "datadog:maven-package"
)

var SeverityMapper = map[models.SeverityType]cyclonedx.ScoringMethod{
	models.SeverityCVSSV2: cyclonedx.ScoringMethodCVSSv2,
	models.SeverityCVSSV3: cyclonedx.ScoringMethodCVSSv3,
	models.SeverityCVSSV4: cyclonedx.ScoringMethodCVSSv4,
}
