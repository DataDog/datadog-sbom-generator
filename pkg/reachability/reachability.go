package reachability

import (
	"log"
	"os"
	"path/filepath"

	"github.com/datadog/datadog-sbom-generator/internal/http"
	"github.com/datadog/datadog-sbom-generator/pkg/models"
	"github.com/datadog/datadog-sbom-generator/pkg/reachability/codefile"
)

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
func PerformReachabilityAnalysis(purls []string, directoryPaths []string) models.ReachabilityAnalysis {
	log.Println("fetching symbols to perform a reachability analysis")
	resp, err := http.PostResolveVulnerableSymbols(purls)
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
				javaReachabilityDetector.Detect(dir, path, detectionResults, advisoriesToCheckPerLanguage["java"])
			default:
				return nil
			}

			return nil
		})

		if err != nil {
			javaReachabilityDetector.Close()
			log.Fatalf("error walking the path: %v\n", err)
		}
	}

	purlToReachabilityAnalysisResults := getPurlsToReachabilityAnalysisResults(advisoriesToCheckPerLanguage, detectionResults)

	return models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: purlToReachabilityAnalysisResults,
	}
}
