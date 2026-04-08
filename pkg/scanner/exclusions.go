package scanner

import (
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

type exclusionMatch struct {
	pattern string
	source  exclusionSource
}

type exclusionSource string

const (
	exclusionSourceCLI    exclusionSource = "cli"
	exclusionSourceConfig exclusionSource = "config"
)

// matchExclusion checks both exclusion sources for a scanned file.
func matchExclusion(r reporter.Reporter, scanRoot string, repoRoot string, path string, cliExcludePaths []string, configExcludePaths []string) (*exclusionMatch, error) {
	if len(cliExcludePaths) == 0 && len(configExcludePaths) == 0 {
		return nil, nil
	}

	if len(cliExcludePaths) > 0 {
		shouldExcludePath, pattern, err := matchCLIExclusion(scanRoot, path, cliExcludePaths)
		if err != nil {
			return nil, err
		}
		if shouldExcludePath {
			return &exclusionMatch{pattern: pattern, source: exclusionSourceCLI}, nil
		}
	}

	if len(configExcludePaths) > 0 {
		if shouldExcludePath, pattern := matchConfigExclusion(repoRoot, path, configExcludePaths, r); shouldExcludePath {
			return &exclusionMatch{pattern: pattern, source: exclusionSourceConfig}, nil
		}
	}

	return nil, nil
}

// matchCLIExclusion applies CLI --exclude patterns relative to the current scan root.
func matchCLIExclusion(scanRoot string, path string, cliExcludePaths []string) (bool, string, error) {
	return fileposition.ShouldExcludePath(scanRoot, path, cliExcludePaths)
}

// matchConfigExclusion applies unified configuration exclusions relative to the
// repository root.
func matchConfigExclusion(repoRoot string, path string, configExcludePaths []string, r reporter.Reporter) (bool, string) {
	matched, pattern, err := fileposition.MatchConfigExcludePath(repoRoot, path, configExcludePaths)
	if err != nil {
		r.Warnf("[config] Failed to evaluate exclusion pattern: %v\n", err)

		return false, ""
	}

	return matched, pattern
}
