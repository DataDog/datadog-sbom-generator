package reachability

import (
	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/package-url/packageurl-go"
)

// purlTypeToLanguageKey maps a PURL type to the language key used to route vulnerable symbols
// to the correct reachability detector.
var purlTypeToLanguageKey = map[string]string{
	packageurl.TypeMaven:  languageKeyJava,
	packageurl.TypeGolang: languageKeyGo,
	packageurl.TypeNPM:    languageKeyJavaScript,
}

// getAdvisoriesToCheckPerLanguage returns a map of language to advisories with symbols to check.
// PURLs that fail to parse, or whose type has no known reachability detector, are skipped with
// a warning rather than aborting the whole reachability pass. Symbols the language's detector
// can't check are dropped, and so are advisories left with none, so they count as not checked.
func getAdvisoriesToCheckPerLanguage(r reporter.Reporter, resp http.ResolveVulnerableSymbolsResponse) models.AdvisoriesToCheckPerLanguage {
	output := models.AdvisoriesToCheckPerLanguage{}

	for _, result := range resp.Results {
		parsedPurl, err := packageurl.FromString(result.Purl)
		if err != nil {
			r.Warnf("[reachability] Skipping %s: failed to parse PURL: %v", result.Purl, err)
			continue
		}

		language, languageSupported := purlTypeToLanguageKey[parsedPurl.Type]
		if !languageSupported {
			r.Warnf("[reachability] Skipping %s: no reachability support for PURL type %s", result.Purl, parsedPurl.Type)
			continue
		}

		// Iterate over the vulnerable symbols and populate the output
		for _, symbolDetails := range result.VulnerableSymbols {
			symbols := make([]models.Symbols, 0, len(symbolDetails.Symbols))
			for _, symbol := range symbolDetails.Symbols {
				s := models.Symbols{
					Type:  symbol.Type,
					Value: symbol.Value,
					Name:  symbol.Name,
				}
				if isSymbolSupported(language, s) {
					symbols = append(symbols, s)
				}
			}

			if len(symbols) == 0 {
				continue
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

// isSymbolSupported reports whether the detector for languageKey can check symbols of this type.
func isSymbolSupported(languageKey string, s models.Symbols) bool {
	switch languageKey {
	case languageKeyGo:
		return s.Type == codefile.SymbolTypeFunction
	case languageKeyJava:
		return s.Type == codefile.SymbolTypeClass
	case languageKeyJavaScript:
		return s.Type == codefile.SymbolTypeFunction || s.Type == codefile.SymbolTypeClass
	default:
		return false
	}
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
