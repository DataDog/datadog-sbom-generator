package reachability

import (
	"log"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"

	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
)

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
func PerformReachabilityAnalysis(enabled bool, purls []string, directoryPaths []string, excludePaths []string, ddBaseURL string, ddJwtToken string) models.ReachabilityAnalysis {
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

			relativePath := fileposition.ToRelativePath(dir, path)

			for _, pattern := range excludePaths {
				matched, err := filepath.Match(pattern, relativePath)
				if err != nil {
					log.Printf("Invalid exclusion glob pattern %s: %v\n", pattern, err)
				}
				if matched {
					log.Printf("Skipping %s file due to exclusion rule %s\n", path, pattern)
					return nil
				}
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
