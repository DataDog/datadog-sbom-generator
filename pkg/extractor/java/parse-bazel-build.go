package java

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	bazelPackageManager      = models.Bazel
	bazelOfficiallySupported = true

	bazelBuildFilename   = "BUILD.bazel"
	bazelBuildFilenamAlt = "BUILD"
)

// BazelBuildExtractor parses BUILD.bazel files to extract internal module
// dependencies (//path/to/module refs) as ProjectDeps. External dependencies
// (artifact(...)) are ignored — those are captured by MavenInstallExtractor
// via maven_install.json.
type BazelBuildExtractor struct{}

func (e BazelBuildExtractor) ShouldExtract(path string) bool {
	base := filepath.Base(path)
	return base == bazelBuildFilename || base == bazelBuildFilenamAlt
}

func (e BazelBuildExtractor) IsOfficiallySupported() bool {
	return bazelOfficiallySupported
}

func (e BazelBuildExtractor) PackageManager() models.PackageManager {
	return bazelPackageManager
}

func (e BazelBuildExtractor) IsManifestParser() bool {
	return false
}

// Extract returns an empty slice — BUILD.bazel does not declare external
// package dependencies directly. Those come from maven_install.json.
func (e BazelBuildExtractor) Extract(_ extractor.DepFile, _ extractor.ScanContext) ([]extractor.PackageDetails, error) {
	return []extractor.PackageDetails{}, nil
}

// GetArtifact reads the BUILD.bazel file and extracts internal module references
// (//path/to/module) as ProjectDeps. External deps (artifact(...)) are filtered
// out. Named targets (//path:name) are resolved to their directory's BUILD file.
func (e BazelBuildExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:  f.Path(),
			Ecosystem: models.EcosystemMaven,
		},
	}

	if ctx.RootDir != "" {
		artifact.ProjectDeps = extractBazelInternalDeps(content, ctx.RootDir)
	}

	return artifact, nil
}

// extractBazelInternalDeps scans the entire BUILD file content for string
// literals matching internal Bazel target references (//path/to/module or
// //path/to/module:target). It resolves each to a filesystem path and returns
// ArtifactDetail entries for existing BUILD files. Duplicates are deduplicated.
func extractBazelInternalDeps(content []byte, rootDir string) []models.ArtifactDetail {
	// Resolve rootDir to an absolute path so that ProjectDeps paths match the
	// artifact filenames produced by the scanner (which relativizes from cwd).
	if absRoot, err := filepath.Abs(rootDir); err == nil {
		rootDir = absRoot
	}

	// Strip Starlark line comments (#...) so that commented-out labels like
	// # "//libs/old" are not mistaken for active dependencies.
	commentRegex := cachedregexp.MustCompile(`(?m)#[^\n]*`)
	filtered := commentRegex.ReplaceAll(content, nil)

	// Strip load(...) blocks before scanning for internal refs. load() arguments
	// reference Starlark macro/rule definition files (build infrastructure),
	// not Java modules that end up in the service binary. We remove the entire
	// block (including multiline loads) to avoid capturing their string labels.
	loadBlockRegex := cachedregexp.MustCompile(`(?ms)^\s*load\([^)]*\)`)
	filtered = loadBlockRegex.ReplaceAll(filtered, nil)

	// Match all string literals that start with // and reference internal targets.
	// This captures both inline deps = ["//foo"] and variable patterns like
	// LIBRARY_DEPS = ["//foo"]. The regex intentionally scans the full file
	// rather than parsing deps blocks, matching the approach described in the spec.
	internalRefRegex := cachedregexp.MustCompile(`["'](//[^"']+)["']`)
	matches := internalRefRegex.FindAllSubmatch(filtered, -1)

	var deps []models.ArtifactDetail
	seen := make(map[string]struct{})

	for _, m := range matches {
		ref := string(m[1]) // e.g. "//domains/foo/libs/bar" or "//domains/foo/libs/bar:target"

		// Skip artifact() wrapped entries — these are external Maven deps.
		// The regex captures them too, but they won't start with // after the
		// artifact( prefix. Actually, artifact("group:name") doesn't start with
		// //, so they are naturally filtered. But be defensive:
		if strings.Contains(ref, ":") && !strings.HasPrefix(ref, "//") {
			continue
		}

		// Strip the // prefix
		path := strings.TrimPrefix(ref, "//")

		// Strip :target suffix if present (e.g. "foo/bar:baz" -> "foo/bar")
		if idx := strings.LastIndex(path, ":"); idx >= 0 {
			path = path[:idx]
		}

		// Try BUILD.bazel first, then BUILD
		for _, buildFileName := range []string{bazelBuildFilename, bazelBuildFilenamAlt} {
			depPath := filepath.Join(rootDir, path, buildFileName)
			if _, err := os.Stat(depPath); err != nil {
				continue
			}
			if _, dup := seen[depPath]; dup {
				break
			}
			seen[depPath] = struct{}{}
			deps = append(deps, models.ArtifactDetail{Filename: depPath})

			break
		}
	}

	return deps
}

var _ extractor.ArtifactExtractor = BazelBuildExtractor{}
var _ extractor.ManifestExtractor = BazelBuildExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.BazelBuildFilePath, BazelBuildExtractor{})
}
