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

	// Matches individual quoted project references like ':subA' or ":subA" within an include argument list.
	includeRefRe = cachedregexp.MustCompile(`['"]([^'"]+)['"]`)
)

// parseGradleSettingsProjectName reads settings.gradle (or settings.gradle.kts) from
// rootDir and returns the canonical project name for the project whose directory is
// projectDir. Returns "" if no settings file exists, rootDir is empty, or the project
// is not declared in the settings file.
func parseGradleSettingsProjectName(rootDir, projectDir string) string {
	if rootDir == "" {
		return ""
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
// and extracts the group defined there (e.g. via allprojects { group = '...' } or
// a top-level group = '...' assignment). Used as a fallback when a subproject's
// own build file does not declare group, inheriting it from the root instead.
func extractGroupFromRootBuildFile(rootDir string) string {
	if rootDir == "" {
		return ""
	}

	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
		data, err := os.ReadFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}

		if group := extractTopLevelGroup(data); group != "" {
			return group
		}
	}

	return ""
}
