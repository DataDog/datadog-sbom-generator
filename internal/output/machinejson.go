package output

import (
	"encoding/json"
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// PrintJSONResults writes results to the provided writer in JSON format
func PrintJSONResults(vulnResult *models.VulnerabilityResults, outputWriter io.Writer) error {
	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")

	return encoder.Encode(vulnResult)
}
