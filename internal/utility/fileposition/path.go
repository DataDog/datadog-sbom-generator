package fileposition

import (
	"os"
	"path/filepath"
	"strings"
)

func ToRelativePath(scanPath string, packagePath string) string {
	hostPath, err := filepath.Abs(scanPath)
	if err != nil {
		return packagePath
	}
	stats, err := os.Lstat(hostPath)
	if err != nil {
		return packagePath
	}
	if !stats.IsDir() {
		hostPath = filepath.Dir(hostPath)
	}

	// Convert to forward slashes
	// Because this is relative to the root dir, we ignore if the run is on Windows (it would generate path with backslashes)
	path := filepath.ToSlash(strings.TrimPrefix(packagePath, hostPath))
	path = strings.TrimPrefix(path, "/")

	return path
}

// ShouldExcludePath checks if a given path should be excluded based on a list of exclusion patterns.
func ShouldExcludePath(dir, path string, excludePaths []string) (bool, string, error) {
	relativePath, err := filepath.Rel(dir, path)
	if err != nil {
		return false, "", err
	}

	if relativePath == "" {
		return false, "", nil
	}

	for _, pattern := range excludePaths {
		matched, err := filepath.Match(pattern, relativePath)
		if err != nil {
			return false, "", err
		}

		if matched {
			return true, pattern, nil
		}
	}

	return false, "", nil
}
