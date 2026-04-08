package scanner

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/bmatcuk/doublestar/v4"
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
		shouldExcludePath, pattern, err := matchConfigExclusion(repoRoot, path, configExcludePaths, r)
		if err != nil {
			return nil, err
		}
		if shouldExcludePath {
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
func matchConfigExclusion(repoRoot string, path string, configExcludePaths []string, r reporter.Reporter) (bool, string, error) {
	if repoRoot == "" {
		return false, "", nil
	}

	relativePath, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return false, "", err
	}

	relativePath = filepath.ToSlash(relativePath)
	if relativePath == "" {
		return false, "", nil
	}

	for _, pattern := range configExcludePaths {
		matched, err := matchesConfigIgnorePattern(relativePath, pattern)
		if err != nil {
			r.Warnf("[config] Failed to evaluate exclusion pattern %q: %v\n", pattern, err)
			continue
		}
		if matched {
			return true, pattern, nil
		}
	}

	return false, "", nil
}

// matchesConfigIgnorePattern mirrors the static analyzer's ignore-path matching:
// glob patterns use doublestar, while plain paths use exact-or-prefix matching.
func matchesConfigIgnorePattern(relativePath string, pattern string) (bool, error) {
	cleanPattern := strings.TrimSuffix(filepath.ToSlash(pattern), "/")
	if strings.ContainsAny(cleanPattern, "*?[") {
		matched, err := doublestar.PathMatch(cleanPattern, relativePath)
		if err != nil {
			return false, fmt.Errorf("invalid glob pattern: %w", err)
		}

		return matched, nil
	}

	return relativePath == cleanPattern || strings.HasPrefix(relativePath, cleanPattern+"/"), nil
}
