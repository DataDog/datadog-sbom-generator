package pathexclusion

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// MatchConfigExcludePath checks if path should be excluded based on unified config
// ignore-paths patterns, resolved relative to repoRoot. Glob patterns use doublestar;
// plain paths use exact-or-prefix matching.
func MatchConfigExcludePath(repoRoot, path string, configExcludePaths []string) (bool, string, error) {
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
		cleanPattern := strings.TrimSuffix(filepath.ToSlash(pattern), "/")
		if strings.ContainsAny(cleanPattern, "*?[") {
			matched, err := doublestar.PathMatch(cleanPattern, relativePath)
			if err != nil {
				return false, "", fmt.Errorf("invalid glob pattern: %w", err)
			}
			if matched {
				return true, pattern, nil
			}
		} else if relativePath == cleanPattern || strings.HasPrefix(relativePath, cleanPattern+"/") {
			return true, pattern, nil
		}
	}

	return false, "", nil
}
