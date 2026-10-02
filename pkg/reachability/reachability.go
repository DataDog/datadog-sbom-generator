package reachability

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/DataDog/datadog-sbom-generator/internal/customgitignore"
	"github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/pathexclusion"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile/golang"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"golang.org/x/sync/errgroup"
)

// languageKeyGo and languageKeyJava are the language keys used to route vulnerable symbols to
// the correct reachability detector. They're shared across extensionToLanguageKey,
// languageKeyToDetectorFactory, and purlTypeToLanguageKey (utils.go) so a typo in one map can't
// silently drift from the others.
const (
	languageKeyGo         = "go"
	languageKeyJava       = "java"
	languageKeyJavaScript = "javascript"
)

// extensionToLanguageKey maps a file extension to the language key used both to look up
// advisories to check and to select a detector pool. All JavaScript/TypeScript/JSX/TSX
// extensions share one language key; the detector itself picks the right tree-sitter grammar
// (JS, TS, or TSX) internally based on the file extension.
var extensionToLanguageKey = map[string]string{
	".java": languageKeyJava,
	".go":   languageKeyGo,
	".js":   languageKeyJavaScript,
	".jsx":  languageKeyJavaScript,
	".mjs":  languageKeyJavaScript,
	".cjs":  languageKeyJavaScript,
	".ts":   languageKeyJavaScript,
	".mts":  languageKeyJavaScript,
	".cts":  languageKeyJavaScript,
	".tsx":  languageKeyJavaScript,
}

// hardcodedExcludedDirNames are directory names never worth walking into during reachability
// analysis: node_modules (JS/TS dependency tree) and the universal .git. Checked
// unconditionally, independent of useGitIgnore/--no-ignore - mirroring pkg/scanner's scanDir,
// which unconditionally skips .git with no toggle. Not user-configurable.
var hardcodedExcludedDirNames = map[string]struct{}{
	".git":         {},
	"node_modules": {},
}

// languageKeyToDetectorFactory constructs a new Detector for a given language key.
var languageKeyToDetectorFactory = map[string]func(reporter.Reporter) (codefile.Detector, error){
	languageKeyJava: func(r reporter.Reporter) (codefile.Detector, error) { return java.NewJavaReachableDetector(r) },
	languageKeyGo:   func(r reporter.Reporter) (codefile.Detector, error) { return golang.NewGoReachableDetector(r) },
	languageKeyJavaScript: func(r reporter.Reporter) (codefile.Detector, error) {
		return javascript.NewJavaScriptReachableDetector(r)
	},
}

type gitIgnoreMatcher struct {
	matcher  gitignore.Matcher
	repoPath string
}

func newGitIgnoreMatcher(dir string, recursive bool) (*gitIgnoreMatcher, error) {
	patterns, repoRootPath, err := customgitignore.ParseGitIgnores(dir, recursive)
	if err != nil {
		return nil, err
	}

	return &gitIgnoreMatcher{matcher: gitignore.NewMatcher(patterns), repoPath: repoRootPath}, nil
}

func (m *gitIgnoreMatcher) match(absPath string, isDir bool) (bool, error) {
	pathInGit, err := filepath.Rel(m.repoPath, absPath)
	if err != nil {
		return false, err
	}

	pathInGitSep := []string{"."}
	if pathInGit != "." {
		pathInGitSep = append(pathInGitSep, strings.Split(pathInGit, string(filepath.Separator))...)
	}

	return m.matcher.Match(pathInGitSep, isDir), nil
}

// PerformReachabilityAnalysis performs a reachability analysis on the given PURLs.
// useGitIgnore and recursive mirror the same flags that pkg/scanner's scanDir uses: when
// useGitIgnore is true, .gitignore patterns are respected during the directory walk (just
// as they are during lockfile scanning), and recursive controls whether child .gitignore
// files are parsed. Independently of both, directories named in hardcodedExcludedDirNames are
// always pruned from the walk, regardless of useGitIgnore.
func PerformReachabilityAnalysis(r reporter.Reporter, purls []string, directoryPaths []string, excludePaths []string, repoRoot string, configExcludePaths []string, ddBaseURL string, ddJwtToken string, useGitIgnore bool, recursive bool) models.ReachabilityAnalysis {
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
		if len(advisoriesToCheckPerLanguage[languageKey]) == 0 {
			continue
		}

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
		var ignoreMatcher *gitIgnoreMatcher
		if useGitIgnore {
			var matcherErr error
			ignoreMatcher, matcherErr = newGitIgnoreMatcher(dir, recursive)
			if matcherErr != nil {
				r.Warnf("[reachability] Unable to parse git ignores for %s: %v\n", dir, matcherErr)
			}
		}

		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// Hardcoded, unconditional pruning - checked first since it's a zero-I/O name
			// comparison, before the .gitignore matcher below does any path work.
			if d.IsDir() {
				if _, excluded := hardcodedExcludedDirNames[d.Name()]; excluded {
					return filepath.SkipDir
				}
			}

			absPath, err := filepath.Abs(path)
			if err != nil {
				absPath = path
			}

			// .gitignore matching — same pattern as pkg/scanner's scanDir.
			if ignoreMatcher != nil {
				matched, matchErr := ignoreMatcher.match(absPath, d.IsDir())
				if matchErr != nil {
					r.Infof("[reachability] Failed to resolve gitignore for %s: %v\n", path, matchErr)
				} else if matched {
					if d.IsDir() {
						return filepath.SkipDir
					}

					return nil
				}
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

			if len(advisoriesToCheckPerLanguage[languageKey]) == 0 {
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
