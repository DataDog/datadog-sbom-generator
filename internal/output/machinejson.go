package output

import (
	"encoding/json"
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// PrintJSONResultsWithPretty writes results to the provided writer in JSON format with optional pretty printing
func PrintJSONResultsWithPretty(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, pretty bool) error {
	encoder := json.NewEncoder(outputWriter)
	if pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(vulnResult)
}
