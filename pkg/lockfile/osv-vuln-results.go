package lockfile

import (
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func ParseOSVScannerResults(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, OSVScannerResultsExtractor{})
}

type OSVScannerResultsExtractor struct{}

func (e OSVScannerResultsExtractor) ShouldExtract(path string) bool {
	// The output will always be a custom json file, so don't return a default should extract
	return false
}

func (e OSVScannerResultsExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	parsedResults := models.VulnerabilityResults{}
	err := json.NewDecoder(f).Decode(&parsedResults)

	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := []models.PackageDetails{}
	for _, res := range parsedResults.Results {
		for _, pkg := range res.Packages {
			if pkg.Package.Commit != "" { // Prioritize results
				packages = append(packages, models.PackageDetails{
					Commit:         pkg.Package.Commit,
					Name:           pkg.Package.Name,
					PackageManager: models.Unknown,
				})
			} else {
				packages = append(packages, models.PackageDetails{
					Name:           pkg.Package.Name,
					PackageManager: models.Unknown,
					Ecosystem:      pkg.Package.Ecosystem,
					Version:        pkg.Package.Version,
				})
			}
		}
	}

	return packages, nil
}

var _ Extractor = OSVScannerResultsExtractor{}
