package reachability

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"golang.org/x/sync/errgroup"

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

	detectionResults := make(models.DetectionResults)
	// Needed to protect detectionResults from concurrent writes
	var detectionMutex sync.Mutex

	// Parallel for reachability scanning
	ctx := context.Background()
	g, ctx := errgroup.WithContext(ctx)

	// Creates a worker pool of Java detectors for thread-safe parsing
	workerCount := runtime.NumCPU()
	detectorPool := make(chan *codefile.ReachabilityJava, workerCount)

	for range workerCount {
		detector, err := codefile.NewJavaReachableDetector()
		if err != nil {
			r.Errorf("[reachability] Failed to create Java reachability detector: %v", err)
			return models.ReachabilityAnalysis{}
		}
		detectorPool <- detector
	}

	// Cleanup all detectors when done
	defer func() {
		close(detectorPool)
		for detector := range detectorPool {
			detector.Close()
		}
	}()

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
				dir := dir
				path := path
				g.Go(func() error {
					// Get a detector from the pool
					detector := <-detectorPool
					// Return detector to pool after it's finished
					defer func() {
						detectorPool <- detector
					}()

					localResults := make(models.DetectionResults)
					err := detector.Detect(ctx, dir, path, localResults, advisoriesToCheckPerLanguage["java"])
					if err != nil {
						return err
					}

					// Merge local results back to main detectionResults with mutex protection
					detectionMutex.Lock()
					for purl, advisoryMap := range localResults {
						if _, exists := detectionResults[purl]; !exists {
							detectionResults[purl] = make(map[string]models.ReachableSymbolLocations)
						}
						for advisoryID, locations := range advisoryMap {
							detectionResults[purl][advisoryID] = append(detectionResults[purl][advisoryID], locations...)
						}
					}
					detectionMutex.Unlock()

					return nil
				})
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

	if gErr := g.Wait(); gErr != nil {
		r.Errorf("[reachability] Failed to process directories: %v", gErr)
		return models.ReachabilityAnalysis{}
	}
	purlToReachabilityAnalysisResults := getPurlsToReachabilityAnalysisResults(advisoriesToCheckPerLanguage, detectionResults)

	return models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: purlToReachabilityAnalysisResults,
	}
}
