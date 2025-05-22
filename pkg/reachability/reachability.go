package reachability

import (
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
)

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
func PerformReachabilityAnalysis(enabled bool, r reporter.Reporter, purls []string, directoryPaths []string, excludePaths []string, ddBaseURL string, ddJwtToken string) models.ReachabilityAnalysis {
	if !enabled {
		r.Infof("[reachability] Reachability analysis is disabled")
		return models.ReachabilityAnalysis{}
	}

	r.Infof("[reachability] Fetching symbols...")
	resp, err := http.PostResolveVulnerableSymbols(purls, ddBaseURL, ddJwtToken)
	if err != nil {
		r.Warnf("[reachability] Failed to fetch symbols: %v\n", err)
		r.Warnf("[reachability] Continuing without reachability information")

		return models.ReachabilityAnalysis{}
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(resp)

	javaReachabilityDetector, err := codefile.NewJavaReachableDetector()
	if err != nil {
		r.Errorf("[reachability] Failed to create Java reachability detector: %v", err)
	}
	defer javaReachabilityDetector.Close()

	detectionResults := make(models.DetectionResults)

	for _, dir := range directoryPaths {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			shouldExcludePath, pattern, err := fileposition.ShouldExcludePath(dir, path, excludePaths)
			if err != nil {
				r.Warnf("[reachability] Failed exclusion of path %s: %v\n", path, err)
			}

			if shouldExcludePath {
				if d.IsDir() {
					return filepath.SkipDir
				}
				r.Infof("[reachability] Skipping %s with exclusion rule: %s\n", path, pattern)

				return nil
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
			r.Errorf("[reachability] Error walking the path: %v\n", err)
			return models.ReachabilityAnalysis{}
		}
	}

	purlToReachabilityAnalysisResults := getPurlsToReachabilityAnalysisResults(advisoriesToCheckPerLanguage, detectionResults)

	return models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: purlToReachabilityAnalysisResults,
	}
}
