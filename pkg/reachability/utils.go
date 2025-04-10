package reachability

import (
	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// getAdvisoriesToCheckPerLanguage returns a map of language to advisories with symbols to check.
func getAdvisoriesToCheckPerLanguage(resp http.ResolveVulnerableSymbolsResponse) models.AdvisoriesToCheckPerLanguage {
	output := models.AdvisoriesToCheckPerLanguage{}

	for _, result := range resp.Results {
		language := "java"

		// Initialize a slice for the language if it doesn't exist
		if _, languageExists := output[language]; !languageExists {
			output[language] = []models.AdvisoryToCheck{}
		}

		// Iterate over the vulnerable symbols and populate the output
		for _, symbolDetails := range result.VulnerableSymbols {
			symbols := make([]models.Symbols, 0, len(symbolDetails.Symbols))
			for _, symbol := range symbolDetails.Symbols {
				symbols = append(symbols, models.Symbols{
					Type:  symbol.Type,
					Value: symbol.Value,
					Name:  symbol.Name,
				})
			}

			output[language] = append(output[language], models.AdvisoryToCheck{
				Purl:       result.Purl,
				AdvisoryID: symbolDetails.AdvisoryID,
				Symbols:    symbols,
			})
		}
	}

	return output
}

// getPurlsToReachabilityAnalysisResults flattens the detection results into a map of PURLs to analysis results.
func getPurlsToReachabilityAnalysisResults(
	advisoriesToCheckPerLanguage models.AdvisoriesToCheckPerLanguage,
	detectionResults models.DetectionResults,
) models.PurlToReachabilityAnalysisResults {
	purlToReachabilityAnalysisResults := make(models.PurlToReachabilityAnalysisResults)

	// We iterate over the advisories checked as we need to report back the advisories we did a
	// reachability analysis for to build the final report.
	for _, advisoriesToCheck := range advisoriesToCheckPerLanguage {
		for _, advisoryToCheck := range advisoriesToCheck {
			// Initialize the reachability analysis results for the PURL if it doesn't exist
			if _, ok := purlToReachabilityAnalysisResults[advisoryToCheck.Purl]; !ok {
				purlToReachabilityAnalysisResults[advisoryToCheck.Purl] = &models.ReachabilityAnalysisResults{
					ReachableVulnerabilities: []models.ReachableVulnerability{},
					AdvisoryIdsChecked:       make([]string, 0, len(advisoriesToCheck)),
				}
			}
			// Add the advisory ID to the list of advisories checked for this PURL
			purlToReachabilityAnalysisResults[advisoryToCheck.Purl].AdvisoryIdsChecked = append(
				purlToReachabilityAnalysisResults[advisoryToCheck.Purl].AdvisoryIdsChecked,
				advisoryToCheck.AdvisoryID,
			)

			// Was anything reachable for this PURL?
			if advisoryIdsToReachableVulns, purlHasReachableVulns := detectionResults[advisoryToCheck.Purl]; purlHasReachableVulns {
				if reachableVulns, reachableVulnsExistForAdvisory := advisoryIdsToReachableVulns[advisoryToCheck.AdvisoryID]; reachableVulnsExistForAdvisory {
					purlToReachabilityAnalysisResults[advisoryToCheck.Purl].ReachableVulnerabilities = append(
						purlToReachabilityAnalysisResults[advisoryToCheck.Purl].ReachableVulnerabilities,
						models.ReachableVulnerability{
							AdvisoryID:               advisoryToCheck.AdvisoryID,
							ReachableSymbolLocations: reachableVulns,
						},
					)
				}
			}
		}
	}

	return purlToReachabilityAnalysisResults
}
