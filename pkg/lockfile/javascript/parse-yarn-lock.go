package javascript

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func shouldSkipYarnLine(line string) bool {
	return line == "" || strings.HasPrefix(line, "#")
}

// Example of block:
//
// "semver@npm:^7.3.3, semver@npm:^7.3.4":
//
//	version: 7.7.3
//	dependencies:
//	 semver: "foobar:^6.0.0"
//
// Where several targetVersions of 'semver' resolve to the same version: "7.7.3"
// In this case, we return 2 YarnPackage. One per TargetVersions.
func parseYarnPackageBlock(block []string) []YarnPackage {
	name, targetVersions, workspacePath := extractYarnPackageNameAndTargetVersions(block[0]) // look at the first line

	packages := make([]YarnPackage, 0, len(targetVersions))
	version := determineYarnPackageVersion(block)
	resolution := determineYarnPackageResolution(block)
	dependencies := determineYarnPackageDependencies(block)

	// Create one YarnPackage per target version
	for _, targetVersion := range targetVersions {
		packages = append(packages, YarnPackage{
			Name:          name,
			Version:       version,
			TargetVersion: targetVersion,
			Resolution:    resolution,
			Dependencies:  dependencies,
			WorkspacePath: workspacePath,
		})
	}

	return packages
}

// findLastNonEmptyLineInRange finds the 1-indexed line number of the last non-empty line
// within the 0-indexed range [startIdx, endIdx].
func findLastNonEmptyLineInRange(lines []string, startIdx, endIdx int) int {
	if endIdx >= len(lines) {
		endIdx = len(lines) - 1
	}

	for i := endIdx; i >= startIdx; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return i + 1 // 1-indexed
		}
	}

	return startIdx + 1
}

// buildYarnBlockPosition creates a FilePosition from 1-indexed start and end line numbers.
func buildYarnBlockPosition(lines []string, startLine, endLine int) models.FilePosition {
	colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(lines[startLine-1])
	colEnd := fileposition.GetLastNonEmptyCharacterIndexInLine(lines[endLine-1])

	return models.FilePosition{
		Line:   models.Position{Start: startLine, End: endLine},
		Column: models.Position{Start: colStart, End: colEnd},
	}
}

func groupYarnPackageLines(scanner *bufio.Scanner, lines []string) []YarnPackage {
	var groups []YarnPackage
	var group []string
	var blockStartLine int // 1-indexed line number of block start

	lineNum := 0
	var line string
	for scanner.Scan() {
		lineNum++
		line = scanner.Text()

		if shouldSkipYarnLine(line) {
			continue
		}

		// represents the lineStart of a new dependency
		if !strings.HasPrefix(line, " ") {
			if len(group) > 0 {
				packages := parseYarnPackageBlock(group)
				// Set BlockLocation on each package
				blockEndLine := findLastNonEmptyLineInRange(lines, blockStartLine-1, lineNum-2)
				for i := range packages {
					packages[i].BlockLocation = buildYarnBlockPosition(lines, blockStartLine, blockEndLine)
				}
				groups = append(groups, packages...)
			}
			group = make([]string, 0)
			blockStartLine = lineNum
		}

		group = append(group, line)
	}

	if len(group) > 0 {
		packages := parseYarnPackageBlock(group)
		blockEndLine := findLastNonEmptyLineInRange(lines, blockStartLine-1, len(lines)-1)
		for i := range packages {
			packages[i].BlockLocation = buildYarnBlockPosition(lines, blockStartLine, blockEndLine)
		}
		groups = append(groups, packages...)
	}

	return groups
}

func extractYarnPackageNameAndTargetVersions(line string) (string, []string, string) {
	line = strings.ReplaceAll(line, "\"", "")
	line = strings.TrimSuffix(line, ":")
	parts := strings.Split(line, ",")

	var name, right string
	targetVersions := make([]string, 0)

	for _, part := range parts {
		part = strings.TrimPrefix(part, " ")
		partIsScoped := strings.HasPrefix(part, "@")
		if partIsScoped {
			part = strings.TrimPrefix(part, "@")
		}

		_name, _right, _ := strings.Cut(part, "@")
		if len(name) == 0 {
			name = _name
			if partIsScoped {
				name = "@" + name
			}
		}
		right = _right

		if strings.HasPrefix(right, "npm:") {
			right = strings.TrimPrefix(right, "npm:")
			if strings.Contains(right, "@") {
				resolvedName, resolvedTargetVersions, _ := extractYarnPackageNameAndTargetVersions(right)
				name = resolvedName
				targetVersions = append(targetVersions, resolvedTargetVersions...)

				continue
			}
		}

		// for yarn v2 - it could include these prefixes even when they are not included in package.json
		prefixes := []string{"file", "link", "portal"}
		for _, prefix := range prefixes {
			if strings.HasPrefix(right, prefix+":") {
				right = strings.TrimPrefix(right, prefix+":")
			}
		}

		// for yarn v2 - "file:path/to/dir::locator=...%40workspace%3A.": -> file:path/to/dir
		right, _, _ = strings.Cut(right, "::locator")

		targetVersions = append(targetVersions, right)
	}

	// Extract workspace path if present
	workspacePath := ""
	for _, version := range targetVersions {
		if strings.HasPrefix(version, yarnWorkspaceVersionMarker) {
			workspacePath = strings.TrimPrefix(version, yarnWorkspaceVersionMarker)
			break
		}
	}

	return name, targetVersions, workspacePath
}

// extractVersionFromGitResolution attempts to extract a version from git-based package resolution.
// This is used as a fallback when the version field is empty (common with Bower packages and git dependencies).
// Returns the git commit hash if found, or empty string otherwise.
func extractVersionFromGitResolution(group []string) string {
	resolution := determineYarnPackageResolution(group)
	if resolution == "" {
		return ""
	}

	commit := tryExtractCommit(resolution)

	return commit
}

func determineYarnPackageVersion(group []string) string {
	// Updated regex to handle empty versions (changed + to * for zero or more characters)
	re := cachedregexp.MustCompile(`^ {2}"?version"?:? "?([\w-.+]*)"?$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			version := matched[1]
			// If version is empty, try to extract from resolution (for git-based packages)
			if version == "" {
				return extractVersionFromGitResolution(group)
			}

			return version
		}
	}

	// Version field not found in the package block
	return ""
}

/*
You can find the line parsing regex in action here: https://regex101.com/r/QoJ3b7/3
All expected formats are defined in the regex documentation
*/
func determineYarnPackageDependencies(group []string) []YarnDependency {
	indentCount := -1
	results := make([]YarnDependency, 0)
	lineParsing := cachedregexp.MustCompile(`^"?(?P<package_name>[^\s":]+)"?\s*:?\s*"?(?P<targeted_version>[^"\n]+)"?$`)

	for _, line := range group {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "dependencies") || strings.HasPrefix(trimmed, "optionalDependencies") {
			// start of the dependencies or optionalDependencies section
			indentCount = len(line) - len(trimmed)
		} else if indentCount != -1 && len(line)-len(trimmed) == indentCount {
			// end of the current dependencies section, reset to look for next section
			indentCount = -1
		} else if indentCount != -1 {
			// A line inside the dependencies section, lets parse it
			match := lineParsing.FindStringSubmatch(trimmed)
			if len(match) < 3 {
				// The line have an invalid format, lets skip it
				continue
			}
			name := match[1]
			registry, version, found := strings.Cut(match[2], ":")

			if !found {
				registry = "npm"
				version = match[2]
			}

			results = append(results, YarnDependency{
				Name:     name,
				Version:  version,
				Registry: registry,
			})
		}
	}

	return results
}

func determineYarnPackageResolution(group []string) string {
	re := cachedregexp.MustCompile(`^ {2}"?(?:resolution:|resolved)"? "([^ '"]+)"$`)

	for _, s := range group {
		matched := re.FindStringSubmatch(s)

		if matched != nil {
			return matched[1]
		}
	}

	// todo: decide what to do here - maybe panic...?
	return ""
}

func tryExtractCommit(resolution string) string {
	// language=GoRegExp
	matchers := []string{
		// ssh://...
		// git://...
		// git+ssh://...
		// git+https://...
		`(?:^|.+@)(?:git(?:\+(?:ssh|https))?|ssh)://.+#(\w+)$`,
		// https://....git/...
		`(?:^|.+@)https://.+\.git#(\w+)$`,
		`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`,
		`.+#commit[:=](\w+)$`,
		// github:...
		// gitlab:...
		// bitbucket:...
		`^(?:github|gitlab|bitbucket):.+#(\w+)$`,
	}

	for _, matcher := range matchers {
		re := cachedregexp.MustCompile(matcher)
		matched := re.FindStringSubmatch(resolution)

		if matched != nil {
			return matched[1]
		}
	}

	u, err := url.Parse(resolution)

	if err == nil {
		gitRepoHosts := []string{
			"bitbucket.org",
			"github.com",
			"gitlab.com",
		}

		for _, host := range gitRepoHosts {
			if u.Host != host {
				continue
			}

			if u.RawQuery != "" {
				queries := u.Query()

				if queries.Has("ref") {
					return queries.Get("ref")
				}
			}

			return u.Fragment
		}
	}

	return ""
}

/*
buildDependencyTree leverage yarn lockfile format to build the subtree of a package

`rootPkgName` is the name of the package which needs its dependency tree to be built
`rootPkgTargetVersion` is the constraint of the package we search (for example ^1.0.0)
`rootPkgRegistry` is the registry used to download this dependency (defaults to npm)
`dependencies` is the representation of the yarn lockfile, where the key is either package name, registry and target version
or package name and target version and the value is the package definition in Yarn format
`packagesIndex` is an index of all package in datadog-sbom-generator format where the key is the package name and the package version

This methods build the dependency tree by looking at the yarn dependencies definition and matching every transitive dependency
with the index to get a pointer to the datadog-sbom-generator formatted child package
*/
func buildDependencyTree(rootPkgName, rootPkgTargetVersion, rootPkgRegistry string, dependencies map[string]YarnPackage, packagesIndex map[string]*lockfile.PackageDetails) []*lockfile.PackageDetails {
	results := make([]*lockfile.PackageDetails, 0)
	pkg, ok := dependencies[rootPkgName+"@"+rootPkgTargetVersion]
	if !ok {
		pkg, ok = dependencies[rootPkgName+"@"+rootPkgRegistry+":"+rootPkgTargetVersion]
		if !ok {
			return []*lockfile.PackageDetails{}
		}
	}

	for _, dependency := range pkg.Dependencies {
		dependentPackage, ok := dependencies[dependency.Name+"@"+dependency.Version]
		if !ok {
			dependentPackage, ok = dependencies[dependency.Name+"@"+dependency.Registry+":"+dependency.Version]
			if !ok {
				continue
			}
		}
		dep, exists := packagesIndex[dependentPackage.Name+"@"+dependentPackage.TargetVersion]
		if exists {
			results = append(results, dep)
		}
	}

	return results
}

func parseYarnPackage(dependency YarnPackage, filePath string) lockfile.PackageDetails {
	if dependency.Version == "" {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"Failed to determine version of %s while parsing a yarn.lock - please report this!\n",
			dependency.Name,
		)
	}

	var nameLocation *models.FilePosition
	if dependency.WorkspacePath != "" {
		nameLocation = &models.FilePosition{Filename: dependency.WorkspacePath}
	}

	blockLocation := dependency.BlockLocation
	blockLocation.Filename = filePath

	return lockfile.PackageDetails{
		Name:           dependency.Name,
		Version:        dependency.Version,
		TargetVersions: []string{dependency.TargetVersion},
		PackageManager: yarnPackageManager,
		Ecosystem:      models.EcosystemNPM,
		Commit:         tryExtractCommit(dependency.Resolution),
		NameLocation:   nameLocation,
		BlockLocation:  blockLocation,
		LocationRole:   models.LocationRoleLockfile,
	}
}

func indexByTargetVersion(packages []YarnPackage) map[string]YarnPackage {
	index := make(map[string]YarnPackage)

	for _, pkg := range packages {
		index[pkg.Name+"@"+pkg.TargetVersion] = pkg
	}

	return index
}

func indexByNameAndVersions(packages []lockfile.PackageDetails) map[string]*lockfile.PackageDetails {
	result := make(map[string]*lockfile.PackageDetails)
	for index, pkg := range packages {
		// packages would have been created with a single TargetVersions
		result[pkg.Name+"@"+pkg.TargetVersions[0]] = &packages[index]
	}

	return result
}

func (e YarnLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.YarnFilePath.String()
}

func (e YarnLockExtractor) IsOfficiallySupported() bool {
	return yarnOfficiallySupported
}

func (e YarnLockExtractor) PackageManager() models.PackageManager {
	return yarnPackageManager
}

// isJSONFormat detects whether the yarn.lock content is in JSON format (Yarn v4+) or YAML format (Yarn v1-3).
//
// Yarn v4+ introduced a new JSON lockfile format with version 9+, which has a different structure:
//   - JSON format: {"__metadata": {"version": 9}, "entries": {...}}
//   - YAML format: # yarn lockfile v1
//
// This function checks for JSON by:
//  1. Verifying the content starts with '{' after trimming whitespace
//  2. Checking for the presence of "__metadata" field within the first 200 bytes
//
// This approach is more robust than checking for exact prefixes because it handles:
//   - Files with leading whitespace/newlines
//   - Pretty-printed JSON with varying indentation
//   - Minified JSON
//
// The function only examines the first 200 bytes for performance when called during format detection.
func isJSONFormat(content []byte) bool {
	trimmed := strings.TrimSpace(string(content))
	if !strings.HasPrefix(trimmed, "{") {
		return false
	}
	// Check if __metadata appears in the first 200 bytes (after any whitespace)
	return strings.Contains(trimmed[:min(200, len(trimmed))], `"__metadata"`)
}

// parseYarnBerryJSON parses Yarn v4+ JSON lockfile format (version 9+) into YarnPackage structures.
//
// Yarn Berry (v4+) introduced a new JSON-based lockfile format to improve parsing performance and reliability.
// The format structure is:
//
//	{
//	  "__metadata": {
//	    "version": 9,
//	    "cacheKey": "..."
//	  },
//	  "entries": {
//	    "package@npm:^1.0.0": {
//	      "version": "1.0.0",
//	      "resolution": { "version": "1.0.0" },
//	      "dependencies": { "dep": "npm:^2.0.0" },
//	      "checksum": "..."
//	    }
//	  }
//	}
//
// This function:
//  1. Unmarshals the JSON into the YarnBerryJSON type structure
//  2. Iterates through all entries in the lockfile
//  3. Extracts package name, target versions, and workspace paths from entry keys
//  4. Converts the JSON dependency map into YarnDependency slices
//  5. Creates one YarnPackage per target version (handles multi-version resolution)
//
// Entry keys follow the format: "package@npm:targetVersion" or "package@targetVersion"
// Dependencies are stored as maps with registry-prefixed versions: {"dep": "npm:^1.0.0"}
//
// Returns a slice of YarnPackage structs compatible with the existing YAML parser output,
// allowing the rest of the extraction logic to work identically for both formats.
// extractYarnBerryJSONPositions scans JSON lines for entry keys within the "entries" object.
// Entry keys appear as "    \"package@npm:^1.0.0\": {" at 4-space indent inside "entries".
func extractYarnBerryJSONPositions(lines []string) map[string]models.FilePosition {
	positions := make(map[string]models.FilePosition)

	inEntries := false
	var currentKey string
	braceDepth := 0

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Detect "entries": {
		if !inEntries && strings.Contains(trimmed, `"entries"`) && strings.HasSuffix(trimmed, "{") {
			inEntries = true
			braceDepth = 1

			continue
		}

		if !inEntries {
			continue
		}

		// Track brace depth
		for _, ch := range trimmed {
			if ch == '{' {
				braceDepth++
			} else if ch == '}' {
				braceDepth--
			}
		}

		if braceDepth <= 0 {
			// Close last entry
			if currentKey != "" {
				closeBerryEntry(positions, currentKey, i, lines)
				currentKey = ""
			}

			inEntries = false

			continue
		}

		// Entry key at depth 1 (exactly 4-space indent, opens an object): "    \"package@npm:^1.0.0\": {"
		// Require HasSuffix("{") to avoid false positives on internal fields like "checksum": "..."
		// which also sit at depth 2 but do not open a new brace.
		if braceDepth == 2 && strings.HasSuffix(trimmed, "{") && strings.HasPrefix(line, "    ") {
			// This is a new entry key
			if currentKey != "" {
				closeBerryEntry(positions, currentKey, i, lines)
			}

			// Extract the key between quotes
			firstQuote := strings.Index(trimmed, `"`)
			lastQuote := strings.Index(trimmed[firstQuote+1:], `"`)

			if firstQuote >= 0 && lastQuote >= 0 {
				key := trimmed[firstQuote+1 : firstQuote+1+lastQuote]
				currentKey = key

				colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)

				positions[currentKey] = models.FilePosition{
					Line:   models.Position{Start: lineNum, End: 0},
					Column: models.Position{Start: colStart, End: 0},
				}
			}
		}
	}

	if currentKey != "" {
		closeBerryEntry(positions, currentKey, len(lines), lines)
	}

	return positions
}

func closeBerryEntry(positions map[string]models.FilePosition, key string, beforeIndex int, lines []string) {
	pos := positions[key]
	lastNonEmpty := beforeIndex - 1
	for lastNonEmpty >= 0 && strings.TrimSpace(lines[lastNonEmpty]) == "" {
		lastNonEmpty--
	}

	if lastNonEmpty >= 0 {
		pos.Line.End = lastNonEmpty + 1
		pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[lastNonEmpty])
	} else {
		pos.Line.End = pos.Line.Start
	}

	positions[key] = pos
}

func parseYarnBerryJSON(content []byte, lines []string) ([]YarnPackage, error) {
	var berryJSON YarnBerryJSON
	if err := json.Unmarshal(content, &berryJSON); err != nil {
		return nil, fmt.Errorf("failed to parse yarn.lock JSON: %w", err)
	}

	positions := extractYarnBerryJSONPositions(lines)
	packages := make([]YarnPackage, 0, len(berryJSON.Entries))

	for entryKey, entry := range berryJSON.Entries {
		// Parse entry key: "package@registry:targetVersion"
		name, targetVersions, workspacePath := extractYarnPackageNameAndTargetVersions(entryKey + ":")

		version := entry.Resolution.Version
		resolution := entry.Resolution.Resolution

		// Convert dependencies map to YarnDependency slice
		dependencies := make([]YarnDependency, 0, len(entry.Resolution.Dependencies))
		for depName, depVersion := range entry.Resolution.Dependencies {
			// Parse registry from version if present (e.g., "npm:^1.0.0")
			registry := "npm"
			cleanVersion := depVersion
			if strings.Contains(depVersion, ":") {
				parts := strings.SplitN(depVersion, ":", 2)
				registry = parts[0]
				cleanVersion = parts[1]
			}

			dependencies = append(dependencies, YarnDependency{
				Name:     depName,
				Version:  cleanVersion,
				Registry: registry,
			})
		}

		// Look up position by entry key
		var blockPos models.FilePosition
		if pos, ok := positions[entryKey]; ok {
			blockPos = pos
		}

		// Create one YarnPackage per target version
		for _, targetVersion := range targetVersions {
			packages = append(packages, YarnPackage{
				Name:          name,
				Version:       version,
				TargetVersion: targetVersion,
				Resolution:    resolution,
				Dependencies:  dependencies,
				WorkspacePath: workspacePath,
				BlockLocation: blockPos,
			})
		}
	}

	return packages, nil
}

func (e YarnLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("error reading yarn.lock: %w", err)
	}

	lines := fileposition.BytesToLines(content)

	var yarnPackages []YarnPackage
	if isJSONFormat(content) {
		// Parse JSON format (Yarn v4+)
		yarnPackages, err = parseYarnBerryJSON(content, lines)
		if err != nil {
			return []lockfile.PackageDetails{}, err
		}
	} else {
		// Parse YAML-like format (Yarn v1-3)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		yarnPackages = groupYarnPackageLines(scanner, lines)

		if err := scanner.Err(); err != nil {
			return []lockfile.PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
		}
	}

	yarnPackageIndex := indexByTargetVersion(yarnPackages)

	// Separate workspace packages from root packages
	workspaces := make([]YarnPackage, 0)
	allResolvedPackages := make([]YarnPackage, 0)

	for _, yarnPackage := range yarnPackages {
		if yarnPackage.Name == "__metadata" {
			continue
		}
		// Workspace packages have -use.local versions and workspace: resolutions
		if strings.Contains(yarnPackage.Version, yarnLocalVersionMarker) || strings.Contains(yarnPackage.Resolution, yarnWorkspaceResolutionMarker) {
			workspaces = append(workspaces, yarnPackage)
		} else {
			allResolvedPackages = append(allResolvedPackages, yarnPackage)
		}
	}

	dependencyWorkspaces := createDependencyWorkspaceMap(workspaces, allResolvedPackages)
	packages := createPackageDetails(allResolvedPackages, dependencyWorkspaces, f.Path())

	pkgIndex := indexByNameAndVersions(packages)
	for index, pkg := range packages {
		packages[index].Dependencies = buildDependencyTree(pkg.Name, pkg.TargetVersions[0], "npm", yarnPackageIndex, pkgIndex)
	}

	return packages, nil
}

// Map to track which workspaces declare each dependency
// yarn lockfile represents as a flat list all dependencies, and we need to reconstruct which workspace declare which dependency
func createDependencyWorkspaceMap(workspaces []YarnPackage, allResolvedPackages []YarnPackage) map[string][]string {
	// First, build an index of workspace dependencies
	// Key: dependencyName@targetVersion, Value: workspace paths that declare it
	workspaceDepsIndex := make(map[string][]string)

	for _, workspace := range workspaces {
		workspacePath := workspace.WorkspacePath
		// "." is the value of the root workspace. Let's not use it -> default to empty string
		if workspacePath == "." {
			workspacePath = ""
		}

		for _, dep := range workspace.Dependencies {
			key := dep.Name + "@" + dep.Version
			workspaceDepsIndex[key] = append(workspaceDepsIndex[key], workspacePath)
		}
	}

	dependencyWorkspaces := make(map[string][]string)

	// Now iterate over resolved packages and lookup their workspace
	for _, pkg := range allResolvedPackages {
		// For the lookupKey, we use the pkg.TargetVersion and not pkg.Version because the dependencies
		// listed in the workspace.Dependencies are listed with the target versions, not the resolved versions
		// Meaning: pkg.TargetVersion == workspace.Dependencies.Version
		lookupKey := pkg.Name + "@" + pkg.TargetVersion
		if workspacePaths, exists := workspaceDepsIndex[lookupKey]; exists {
			depKey := getWorkspaceDependencyKey(pkg.Name, pkg.Version, pkg.TargetVersion)
			dependencyWorkspaces[depKey] = workspacePaths
		}
	}

	return dependencyWorkspaces
}

func createPackageDetails(allResolvedPackages []YarnPackage, dependencyWorkspaces map[string][]string, filePath string) []lockfile.PackageDetails {
	packages := make([]lockfile.PackageDetails, 0, len(allResolvedPackages))

	// Create lockfile.PackageDetails for regular packages, with workspace information where applicable
	for _, yarnPackage := range allResolvedPackages {
		basePackage := parseYarnPackage(yarnPackage, filePath)
		depKey := getWorkspaceDependencyKey(yarnPackage.Name, yarnPackage.Version, yarnPackage.TargetVersion)

		if workspacePaths, exists := dependencyWorkspaces[depKey]; exists {
			// Create separate lockfile.PackageDetails for each workspace that declares this dependency with this target version
			// This is required to parse the related <workspace>/package.json and report an accurate location
			// The duplicates will each have a different location and will get merged before creating the SBOM
			for _, workspacePath := range workspacePaths {
				workspacePackage := basePackage
				if workspacePath != "" {
					workspacePackage.NameLocation = &models.FilePosition{Filename: workspacePath}
				}
				packages = append(packages, workspacePackage)
			}
		} else {
			// Regular package not declared by any workspace
			packages = append(packages, basePackage)
		}
	}

	return packages
}

var YarnExtractor = YarnLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageJSONMatcher{}}},
}

func ParseYarnLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, YarnExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.YarnFilePath, YarnExtractor)
}
