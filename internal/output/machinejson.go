package output

import (
	"encoding/json"
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	return PrintJSONResultsWithPretty(vulnResult, outputWriter, true)
}

// PrintJSONResultsWithPretty writes results to the provided writer in JSON format with optional pretty printing
func PrintJSONResultsWithPretty(vulnResult *models.VulnerabilityResults, outputWriter io.Writer, pretty bool) error {
	encoder := json.NewEncoder(outputWriter)
	if pretty {
		encoder.SetIndent("", "  ")
	}

	return encoder.Encode(vulnResult)
}
