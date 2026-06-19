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
	// The \b word boundary prevents matching includeBuild, includeFlat, etc.
	includeRe = cachedregexp.MustCompile(`(?m)^\s*include\b\s*\(?\s*([^)\n]+?)\s*\)?\s*$`)

	// project(':subA').name = 'renamed' or project(":subA").name = "renamed"
	projectNameRe = cachedregexp.MustCompile(`(?m)^\s*project\(\s*['"]([^'"]+)['"]\s*\)\.name\s*=\s*['"]([^'"]+)['"]`)

	// Matches Gradle project path references like ':subA' or ":sub:module" within an
	// include argument list. Requiring the leading ':' avoids false positives from
	// inline comments or other quoted strings in the same line.
	includeRefRe = cachedregexp.MustCompile(`['"](:(?:[^'"]+))['"]`)

	// blockHeaderRe matches the opening of an allprojects { } or subprojects { } block.
	// Used by extractBlockGroup to locate where to start brace-counting.
	blockHeaderRe = cachedregexp.MustCompile(`(?:allprojects|subprojects)\s*\{`)

	// allProjectsBlockHeaderRe matches the opening of an allprojects { } block only.
	// Gradle's allprojects { } applies to the root project; subprojects { } does not.
	allProjectsBlockHeaderRe = cachedregexp.MustCompile(`allprojects\s*\{`)

	// groupAssignRe matches a group = '...' or group = "..." assignment.
	// Used inside the extracted block body after brace-counting delimits the block.
	groupAssignRe = cachedregexp.MustCompile(`\bgroup\s*=\s*['"]([^'"]+)['"]`)
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

// stripGradleComments returns a copy of src with Groovy/Kotlin comment content
// replaced by spaces, preserving byte positions and newlines so that all regexp
// matches on the result remain aligned with the original source.
// Single-line comments (// … \n) and block comments (/* … */) are both handled.
func stripGradleComments(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	i := 0
	for i < len(out) {
		if i+1 < len(out) && out[i] == '/' && out[i+1] == '/' {
			// Single-line comment: blank everything up to (but not including) the newline.
			for i < len(out) && out[i] != '\n' {
				out[i] = ' '
				i++
			}
		} else if i+1 < len(out) && out[i] == '/' && out[i+1] == '*' {
			// Block comment: blank everything including the delimiters, preserve newlines.
			out[i] = ' '
			out[i+1] = ' '
			i += 2
			for i < len(out) {
				if i+1 < len(out) && out[i] == '*' && out[i+1] == '/' {
					out[i] = ' '
					out[i+1] = ' '
					i += 2

					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
				i++
			}
		} else {
			i++
		}
	}

	return out
}

// extractBlockGroup scans all blocks matched by findHeader in src and returns the
// group from the LAST such block that contains a group assignment. Using the last
// assignment mirrors Gradle's evaluation order: when a root build file has both
// allprojects { group = 'com.root' } and subprojects { group = 'com.sub' }, the
// later block wins for subprojects, so we must not stop at the first match.
// Comments are stripped first so that commented-out blocks are not treated as
// live overrides.
// Pass blockHeaderRe.FindIndex to search both allprojects and subprojects blocks;
// pass allProjectsBlockHeaderRe.FindIndex to restrict to allprojects only.
func extractBlockGroup(src []byte, findHeader func([]byte) []int) string {
	src = stripGradleComments(src)
	last := ""
	for searchFrom := 0; searchFrom < len(src); {
		loc := findHeader(src[searchFrom:])
		if loc == nil {
			break
		}

		// absOpen is the absolute position of '{' (last char of the match) in src.
		absOpen := searchFrom + loc[1] - 1
		depth, blockEnd := 0, -1

		for i := absOpen; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					blockEnd = i
				}
			}
			if blockEnd >= 0 {
				break
			}
		}

		if blockEnd < 0 {
			// No matching closing brace — malformed file, stop searching.
			break
		}

		blockBody := src[absOpen+1 : blockEnd]
		if g := findGroupAtTopLevel(blockBody); g != "" {
			last = g
		}

		// Advance past the closing brace and continue scanning for later blocks.
		searchFrom = blockEnd + 1
	}

	return last
}

// findGroupAtTopLevel scans blockBody for a `group = '...'` assignment at the top
// level of the block only (not inside any nested { } sub-block such as a task
// registration). It builds a flat copy of blockBody where nested block contents are
// blanked out, then applies groupAssignRe to find the first top-level group value.
func findGroupAtTopLevel(blockBody []byte) string {
	depth := 0
	flat := make([]byte, len(blockBody))
	for i, b := range blockBody {
		switch b {
		case '{':
			if depth == 0 {
				flat[i] = b
			} else {
				flat[i] = ' '
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
			if depth == 0 {
				flat[i] = b
			} else {
				flat[i] = ' '
			}
		default:
			if depth == 0 {
				flat[i] = b
			} else {
				flat[i] = ' '
			}
		}
	}
	if m := groupAssignRe.FindSubmatch(flat); m != nil {
		return string(m[1])
	}

	return ""
}

// extractGroupFromRootBuildFile reads the root build.gradle / build.gradle.kts and
// returns the group declared inside an allprojects {} or subprojects {} block.
// Used as a fallback for subprojects that do not declare their own group.
func extractGroupFromRootBuildFile(rootDir string) string {
	if rootDir == "" {
		return ""
	}

	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
		data, err := os.ReadFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}

		if g := extractBlockGroup(data, blockHeaderRe.FindIndex); g != "" {
			return g
		}
	}

	return ""
}

// extractAllProjectsGroupFromRootBuildFile reads the root build.gradle /
// build.gradle.kts and returns the group declared inside an allprojects {} block.
// Unlike extractGroupFromRootBuildFile, it excludes subprojects {} blocks because
// Gradle's allprojects { } applies to the root project while subprojects { } does not.
func extractAllProjectsGroupFromRootBuildFile(rootDir string) string {
	if rootDir == "" {
		return ""
	}

	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
		data, err := os.ReadFile(filepath.Join(rootDir, name))
		if err != nil {
			continue
		}

		if g := extractBlockGroup(data, allProjectsBlockHeaderRe.FindIndex); g != "" {
			return g
		}
	}

	return ""
}
