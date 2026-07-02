package reachability

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/pathexclusion"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"golang.org/x/sync/errgroup"
)

// extensionToLanguageKey maps a file extension to the language key used both to look up
// advisories to check and to select a detector pool.
var extensionToLanguageKey = map[string]string{
	".java": "java",
	".go":   "go",
}

// languageKeyToDetectorFactory constructs a new Detector for a given language key.
var languageKeyToDetectorFactory = map[string]func(reporter.Reporter) (codefile.Detector, error){
	"java": func(r reporter.Reporter) (codefile.Detector, error) { return codefile.NewJavaReachableDetector(r) },
	"go":   func(r reporter.Reporter) (codefile.Detector, error) { return codefile.NewGoReachableDetector(r) },
}

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
func PerformReachabilityAnalysis(r reporter.Reporter, purls []string, directoryPaths []string, excludePaths []string, repoRoot string, configExcludePaths []string, ddBaseURL string, ddJwtToken string) models.ReachabilityAnalysis {
	r.Infof("[reachability] Fetching symbols...")
	resp, err := http.PostResolveVulnerableSymbols(purls, ddBaseURL, ddJwtToken)
	if err != nil {
		r.Warnf("[reachability] Failed to fetch symbols: %v\n", err)
		r.Warnf("[reachability] Continuing without reachability information")

		return models.ReachabilityAnalysis{}
	}

	advisoriesToCheckPerLanguage := getAdvisoriesToCheckPerLanguage(r, resp)

	detectionResults := make(models.DetectionResults)
	var detectionMutex sync.Mutex

	workerCount := runtime.NumCPU()

	detectorPools := make(map[string]chan codefile.Detector, len(languageKeyToDetectorFactory))
	for languageKey, factory := range languageKeyToDetectorFactory {
		pool := make(chan codefile.Detector, workerCount)
		for range workerCount {
			detector, err := factory(r)
			if err != nil {
				r.Errorf("[reachability] Failed to create %s reachability detector: %v", languageKey, err)
				return models.ReachabilityAnalysis{}
			}
			pool <- detector
		}
		detectorPools[languageKey] = pool
	}

	defer func() {
		for _, pool := range detectorPools {
			close(pool)
			for detector := range pool {
				detector.Close()
			}
		}
	}()

	eg, ctx := errgroup.WithContext(context.Background())
	eg.SetLimit(workerCount)

	for _, dir := range directoryPaths {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				absPath = path
			}

			shouldExcludePath, pattern, err := fileposition.ShouldExcludePath(dir, path, excludePaths)
			if err != nil {
				r.Warnf("[reachability] Failed exclusion of path %s: %v\n", path, err)
			}

			if !shouldExcludePath {
				var configErrs []error
				shouldExcludePath, pattern, configErrs = pathexclusion.MatchConfigExcludePath(repoRoot, absPath, configExcludePaths)
				for _, configErr := range configErrs {
					r.Warnf("[reachability] Failed config exclusion of path %s: %v\n", path, configErr)
				}
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

			languageKey, supported := extensionToLanguageKey[filepath.Ext(d.Name())]
			if !supported {
				return nil
			}

			pool := detectorPools[languageKey]

			eg.Go(func() error {
				// Get a detector from the pool
				detector := <-pool
				// Return detector to pool after it's finished
				defer func() {
					pool <- detector
				}()

				localResults := make(models.DetectionResults)
				err := detector.Detect(ctx, dir, path, localResults, advisoriesToCheckPerLanguage[languageKey])
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

			return err
		})

		if err != nil {
			r.Errorf("[reachability] Error walking the path: %v\n", err)
			return models.ReachabilityAnalysis{}
		}
	}

	if gErr := eg.Wait(); gErr != nil {
		r.Errorf("[reachability] Failed to process directories: %v", gErr)
		return models.ReachabilityAnalysis{}
	}
	purlToReachabilityAnalysisResults := getPurlsToReachabilityAnalysisResults(advisoriesToCheckPerLanguage, detectionResults)

	return models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: purlToReachabilityAnalysisResults,
	}
}
