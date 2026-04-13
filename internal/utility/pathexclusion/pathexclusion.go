package pathexclusion

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// MatchConfigExcludePath checks if path should be excluded based on unified config
// ignore-paths patterns, resolved relative to repoRoot. Glob patterns use doublestar;
// plain paths use exact-or-prefix matching. Invalid glob patterns are skipped and
// returned as errors so callers can warn without aborting evaluation of remaining patterns.
func MatchConfigExcludePath(repoRoot, path string, configExcludePaths []string) (bool, string, []error) {
	if repoRoot == "" {
		return false, "", nil
	}

	relativePath, err := filepath.Rel(repoRoot, path)
	if err != nil {
		return false, "", []error{err}
	}

	relativePath = filepath.ToSlash(relativePath)
	if relativePath == "" {
		return false, "", nil
	}

	var errs []error

	for _, pattern := range configExcludePaths {
		cleanPattern := strings.TrimSuffix(filepath.ToSlash(pattern), "/")
		if strings.ContainsAny(cleanPattern, "*?[") {
			matched, err := doublestar.PathMatch(cleanPattern, relativePath)
			if err != nil {
				errs = append(errs, fmt.Errorf("invalid glob pattern %q: %w", pattern, err))
				continue
			}
			if matched {
				return true, pattern, errs
			}
		} else if relativePath == cleanPattern || strings.HasPrefix(relativePath, cleanPattern+"/") {
			return true, pattern, errs
		}
	}

	return false, "", errs
}
