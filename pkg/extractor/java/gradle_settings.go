package java

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
)

const (
	settingsGradleFilename    = "settings.gradle"
	settingsGradleKtsFilename = "settings.gradle.kts"
)

// Regex patterns for parsing settings.gradle / settings.gradle.kts.
var (
	// rootProject.name = 'my-app' or rootProject.name = "my-app"
	rootProjectNameRe = cachedregexp.MustCompile(`(?m)^\s*rootProject\.name\s*=\s*['"]([^'"]+)['"]`)

	// include ':subA', ':subB' or include(':subA', ':subB')
	// Captures the full argument string after include.
	includeRe = cachedregexp.MustCompile(`(?m)^\s*include\s*\(?\s*([^)\n]+?)\s*\)?\s*$`)

	// project(':subA').name = 'renamed' or project(":subA").name = "renamed"
	projectNameRe = cachedregexp.MustCompile(`(?m)^\s*project\(\s*['"]([^'"]+)['"]\s*\)\.name\s*=\s*['"]([^'"]+)['"]`)

	// Matches Gradle project path references like ':subA' or ":sub:module" within an
	// include argument list. Requiring the leading ':' avoids false positives from
	// inline comments or other quoted strings in the same line.
	includeRefRe = cachedregexp.MustCompile(`['"](:(?:[^'"]+))['"]`)

	// Matches group inside allprojects { } or subprojects { } blocks.
	// (?s) makes '.' match newlines so the pattern spans the block body.
	// The lazy .*? captures the FIRST `group =` in the block; because the
	// allprojects/subprojects block delimiter itself prevents matching a
	// top-level `group =` from a different block.
	// Known limitation: if the block contains a task with `group = "foo"`
	// before the real `group = 'real'` assignment, the task group would be
	// captured instead. This construction is extremely rare in practice and
	// is outweighed by correctly handling the common case of `group =` appearing
	// after a `repositories { }` or similar nested block.
	// This is intentionally restricted to inherited group declarations:
	// a top-level `group = 'x'` in the root build file applies only to the root
	// project in Gradle, not to subprojects, so we must not use it as a fallback
	// for subproject group resolution.
	inheritedGroupRe = cachedregexp.MustCompile(`(?s)(?:allprojects|subprojects)\s*\{.*?group\s*=\s*['"]([^'"]+)['"]`)
)

// parseGradleSettingsProjectName reads settings.gradle (or settings.gradle.kts) from
// rootDir and returns the canonical project name for the project whose directory is
// projectDir. Returns "" if no settings file exists, rootDir is empty, or the project
// is not declared in the settings file.
func parseGradleSettingsProjectName(rootDir, projectDir string) string {
	if rootDir == "" {
		return ""
	}

	// Normalize rootDir so filepath.Rel works when the scanner is invoked with a
	// relative path (e.g. "datadog-sbom-generator scan ."). DepFile.Path() returns
	// an absolute path, so a relative rootDir would cause filepath.Rel to fail.
	if abs, err := filepath.Abs(rootDir); err == nil {
		rootDir = abs
	}

	content := readSettingsFile(rootDir)
	if content == nil {
		return ""
	}

	// Compute relative path from rootDir to projectDir.
	relPath, err := filepath.Rel(rootDir, projectDir)
	if err != nil {
		return ""
	}

	// Root project case: projectDir == rootDir → relPath is "."
	if relPath == "." {
		if m := rootProjectNameRe.FindSubmatch(content); m != nil {
			return string(m[1])
		}

		return ""
	}

	// Convert filesystem relative path to Gradle project path notation.
	// e.g. "sub/module" → ":sub:module"
	gradlePath := ":" + strings.ReplaceAll(filepath.ToSlash(relPath), "/", ":")

	// Check for project name override first: project(':sub:module').name = 'renamed'
	for _, m := range projectNameRe.FindAllSubmatch(content, -1) {
		if string(m[1]) == gradlePath {
			return string(m[2])
		}
	}

	// Check if the project is declared in an include statement.
	for _, m := range includeRe.FindAllSubmatch(content, -1) {
		argStr := string(m[1])
		// Extract individual project references from the argument string.
		for _, ref := range includeRefRe.FindAllStringSubmatch(argStr, -1) {
			if ref[1] == gradlePath {
				// Return the last segment of the Gradle path as the project name.
				parts := strings.Split(gradlePath, ":")
				return parts[len(parts)-1]
			}
		}
	}

	return ""
}

// readSettingsFile reads settings.gradle or settings.gradle.kts from dir.
// Returns nil if neither file exists.
func readSettingsFile(dir string) []byte {
	for _, name := range []string{settingsGradleFilename, settingsGradleKtsFilename} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			return data
		}
	}

	return nil
}

// extractGroupFromRootBuildFile reads the root build.gradle / build.gradle.kts
// and extracts the group declared inside an allprojects {} or subprojects {} block.
// A top-level `group = 'x'` in the root build file only applies to the root project
// in Gradle and is intentionally NOT used here, to avoid assigning it to subprojects
// that have no group of their own.
func extractGroupFromRootBuildFile(rootDir string) string {
	if rootDir == "" {
		return ""
	}

	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
		data, err := os.ReadFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}

		if m := inheritedGroupRe.FindSubmatch(data); m != nil {
			return string(m[1])
		}
	}

	return ""
}
