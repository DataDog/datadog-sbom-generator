package reachability

import (
	"log"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
)

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
func PerformReachabilityAnalysis(purls []string, directoryPaths []string, enabled bool, ddBaseURL string, ddJwtToken string) models.ReachabilityAnalysis {
	if !enabled {
		log.Println("reachability analysis is disabled")
		return models.ReachabilityAnalysis{}
	}

	log.Println("fetching symbols to perform a reachability analysis")
	resp, err := http.PostResolveVulnerableSymbols(purls, ddBaseURL, ddJwtToken)
	if err != nil {
		log.Printf("failed to fetch symbols for reachability analysis: %v\n", err)
		log.Println("continuing without reachability information")

		return models.ReachabilityAnalysis{}
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(resp)

	javaReachabilityDetector, err := codefile.NewJavaReachableDetector()
	if err != nil {
		log.Fatalf("failed to create Java reachability detector: %v", err)
	}
	defer javaReachabilityDetector.Close()

	detectionResults := make(models.DetectionResults)

	for _, dir := range directoryPaths {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			switch filepath.Ext(d.Name()) {
			case ".java":
				err = javaReachabilityDetector.Detect(dir, path, detectionResults, advisoriesToCheckPerLanguage["java"])
			default:
				return nil
			}

			return err
		})

		if err != nil {
			log.Printf("error walking the path: %v\n", err)
			return models.ReachabilityAnalysis{}
		}
	}

	purlToReachabilityAnalysisResults := getPurlsToReachabilityAnalysisResults(advisoriesToCheckPerLanguage, detectionResults)

	return models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: purlToReachabilityAnalysisResults,
	}
}
