package output

import (
	"errors"
	"io"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/datadog-sbom-generator/internal/output/sbom"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/purl"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// This method creates a CycloneDX SBOM and returns it. Error being returned here are from components being filtered during PURL grouping
func CreateCycloneDXBOM(tool sbom.Tool, vulnResult *models.VulnerabilityResults) (*cyclonedx.BOM, error) {
	resultsByPurl, errs := purl.Group(vulnResult.Results)

	return sbom.BuildCycloneDXBom(tool, resultsByPurl, vulnResult.Artifacts), errors.Join(errs...)
}

// PrintCycloneDXResultsWithPretty writes results to the provided writer in CycloneDX format with optional pretty printing
func PrintCycloneDXResultsWithPretty(tool sbom.Tool, vulnResult *models.VulnerabilityResults, outputWriter io.Writer, pretty bool) error {
	bom, errs := CreateCycloneDXBOM(tool, vulnResult)
	encoder := cyclonedx.NewBOMEncoder(outputWriter, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(pretty)

	if bom == nil {
		return errs
	}
	encodingErr := encoder.EncodeVersion(bom, bom.SpecVersion)

	return errors.Join(encodingErr, errs)
}
