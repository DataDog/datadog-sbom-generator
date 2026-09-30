package javascript

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"maps"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

func getCleanedVersion(sourceFile PnpmLockfile, name, version string) string {
	if strings.HasPrefix(version, "https://codeload.github.com") {
		// This is a link to a tarball, not a version we need to check the resolved version in the package section
		if pkg, ok := sourceFile.Packages[name+"@"+version]; ok {
			return pkg.Version
		}

		return ""
	}

	return strings.Split(version, "(")[0]
}

func getCommitFromVersion(version string) string {
	if strings.HasPrefix(version, "https://codeload.github.com") {
		re := cachedregexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
		matched := re.FindStringSubmatch(version)

		if matched != nil {
			return matched[1]
		}
	}

	return ""
}

func mergeSlices(fromSlices ...[]string) []string {
	result := make(map[string]bool)
	for _, slice := range fromSlices {
		for _, item := range slice {
			result[item] = true
		}
	}

	return slices.Collect(maps.Keys(result))
}

func addDependencyToPackageDetails(dependency extractor.PackageDetails, packageIdentifier string, deps map[string]extractor.PackageDetails) map[string]extractor.PackageDetails {
	if dep, exists := deps[packageIdentifier]; exists {
		newDepGroups := mergeSlices(dep.DepGroups, dependency.DepGroups)
		newTargetedVersions := mergeSlices(dep.TargetVersions, dependency.TargetVersions)

		if len(newDepGroups) > 0 {
			dep.DepGroups = newDepGroups
		}
		if len(newTargetedVersions) > 0 {
			dep.TargetVersions = newTargetedVersions
		}
		dep.IsDirect = dep.IsDirect || dependency.IsDirect
		deps[packageIdentifier] = dep
	} else {
		deps[packageIdentifier] = dependency
	}

	return deps
}

func extractTransitiveDeps(sourceFile PnpmLockfile, root PnpmDirectDependency, targetedKey string, deps map[string]extractor.PackageDetails, positions map[string]models.FilePosition, filePath string) map[string]extractor.PackageDetails {
	// Need to look at dependencies
	visitedSnapshots := make(map[string]bool)
	snapshotQueue := make([]string, 0)
	snapshotQueue = append(snapshotQueue, targetedKey)

	for len(snapshotQueue) > 0 {
		targetedKey = snapshotQueue[0]
		snapshotQueue = snapshotQueue[1:]

		if _, visited := visitedSnapshots[targetedKey]; visited {
			continue
		}

		visitedSnapshots[targetedKey] = true
		snapshot, ok := sourceFile.Snapshots[targetedKey]

		if !ok {
			continue
		}

		for depName, depVersion := range snapshot.Dependencies {
			version := getCleanedVersion(sourceFile, depName, depVersion)
			transitiveDep := extractor.PackageDetails{
				Name:           depName,
				Version:        version,
				Commit:         getCommitFromVersion(depVersion),
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      root.Pkg.DepGroups,
				PackageManager: models.Pnpm,
				IsDirect:       false,
				BlockLocation:  lookupPnpmPosition(depName, version, depVersion, filePath, positions),
				LocationRole:   models.LocationRoleLockfile,
			}
			addDependencyToPackageDetails(transitiveDep, getPnpmDependencyKey(transitiveDep), deps)
			childKey := depName + "@" + depVersion
			snapshotQueue = append(snapshotQueue, childKey)
		}

		for depName, depVersion := range snapshot.OptionalDependencies {
			version := getCleanedVersion(sourceFile, depName, depVersion)
			transitiveDep := extractor.PackageDetails{
				Name:           depName,
				Version:        version,
				Commit:         getCommitFromVersion(depVersion),
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      root.Pkg.DepGroups,
				PackageManager: models.Pnpm,
				IsDirect:       false,
				BlockLocation:  lookupPnpmPosition(depName, version, depVersion, filePath, positions),
				LocationRole:   models.LocationRoleLockfile,
			}
			addDependencyToPackageDetails(transitiveDep, getPnpmDependencyKey(transitiveDep), deps)
			childKey := depName + "@" + depVersion
			snapshotQueue = append(snapshotQueue, childKey)
		}
	}

	return deps
}

func extractDirectDependencies(sourceFile PnpmLockfile, roots []PnpmDirectDependency, dependencies PnpmDependencies, depGroup string, workspacePath string, positions map[string]models.FilePosition, filePath string) []PnpmDirectDependency {
	for dependencyName, dependency := range dependencies {
		var nameLocation *models.FilePosition
		if workspacePath != "" && workspacePath != "." {
			nameLocation = &models.FilePosition{Filename: workspacePath}
		}

		version := getCleanedVersion(sourceFile, dependencyName, dependency.Version)

		roots = append(roots, PnpmDirectDependency{
			Pkg: extractor.PackageDetails{
				Name:           dependencyName,
				Version:        version,
				Commit:         getCommitFromVersion(dependency.Version),
				TargetVersions: []string{dependency.Specifier},
				Ecosystem:      models.EcosystemNPM,
				DepGroups:      []string{depGroup},
				PackageManager: models.Pnpm,
				IsDirect:       true,
				NameLocation:   nameLocation,
				BlockLocation:  lookupPnpmPosition(dependencyName, version, dependency.Version, filePath, positions),
				LocationRole:   models.LocationRoleLockfile,
			},
			Dep:           dependency,
			WorkspacePath: workspacePath,
		})
	}

	return roots
}

// lookupPnpmPosition resolves the FilePosition for a package in the positions map.
// It tries, in order:
//  1. Exact key "name@version" (common case).
//  2. Raw version key "name@rawVersion" for git/tarball deps where the packages: section
//     stores the full URL (e.g. "ansi-regex@https://codeload.github.com/...") but the
//     caller has already cleaned the version to a semver.
//  3. Prefix match "name@version(" for peer-suffixed keys (e.g. "tsutils@3.21.0(typescript@4.9.5)").
//     When multiple peer variants exist for the same base version, picks the earliest by line number.
func lookupPnpmPosition(name, version, rawVersion, filePath string, positions map[string]models.FilePosition) models.FilePosition {
	key := name + "@" + version
	if pos, ok := positions[key]; ok {
		pos.Filename = filePath
		return pos
	}

	// Fallback for git/tarball deps: try the raw (pre-cleaning) version.
	if rawVersion != version {
		rawKey := name + "@" + rawVersion
		if pos, ok := positions[rawKey]; ok {
			pos.Filename = filePath
			return pos
		}
	}

	// Fallback for peer-suffixed keys (e.g. "tsutils@3.21.0(typescript@4.9.5)").
	// When multiple peer variants exist for the same base version, pick the earliest by line number.
	prefix := key + "("
	var best *models.FilePosition
	for k, pos := range positions {
		if strings.HasPrefix(k, prefix) {
			p := pos
			if best == nil || p.Line.Start < best.Line.Start {
				best = &p
			}
		}
	}
	if best != nil {
		best.Filename = filePath
		return *best
	}

	return models.FilePosition{}
}

func parsePnpmLock(sourceFile PnpmLockfile, positions map[string]models.FilePosition, filePath string) []extractor.PackageDetails {
	// First create the deps tree
	// To do so, first look at the packages list, for each package, look into the importers
	// If present in the importers => its direct and we know its scope
	// Then looking at snapshot, we can build its branch

	// Going through the importers to get a direct (prod or dev), then finding the transitives in the snapshot
	directDependencies := make([]PnpmDirectDependency, 0)
	for workspacePath, importer := range sourceFile.Importers {
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.Dependencies, "prod", workspacePath, positions, filePath)
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.OptionalDependencies, "optional", workspacePath, positions, filePath)
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.DevDependencies, "dev", workspacePath, positions, filePath)
		directDependencies = extractDirectDependencies(sourceFile, directDependencies, importer.ConfigDependencies, "config", workspacePath, positions, filePath)
	}

	packages := make(map[string]extractor.PackageDetails)
	for _, direct := range directDependencies {
		packages = addDependencyToPackageDetails(direct.Pkg, getPnpmWorkspaceDependencyKey(direct), packages)
		packages = extractTransitiveDeps(sourceFile, direct, direct.Pkg.Name+"@"+direct.Dep.Version, packages, positions, filePath)
	}

	return slices.Collect(maps.Values(packages))
}

func getPnpmWorkspaceDependencyKey(direct PnpmDirectDependency) string {
	return getWorkspaceDependencyKey(direct.Pkg.Name, direct.Pkg.Version, direct.WorkspacePath)
}

func getPnpmDependencyKey(pkg extractor.PackageDetails) string {
	return getWorkspaceDependencyKey(pkg.Name, pkg.Version, "") // this has no workspace path
}

// closePnpmBlock closes a package block by finding the last non-empty line before index i.
func closePnpmBlock(positions map[string]models.FilePosition, key string, beforeIndex int, lines []string) {
	pos := positions[key]
	// Find last non-empty line before beforeIndex
	lastNonEmpty := beforeIndex - 1
	for lastNonEmpty >= 0 && strings.TrimSpace(lines[lastNonEmpty]) == "" {
		lastNonEmpty--
	}

	if lastNonEmpty >= 0 {
		pos.Line.End = lastNonEmpty + 1 // 1-indexed
		pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[lastNonEmpty])
	} else {
		pos.Line.End = pos.Line.Start
	}

	positions[key] = pos
}

// extractPnpmV9PackagePositions scans YAML lines for package entries under "packages:".
// Package keys appear at 2-space indent (e.g. "  acorn@8.11.3:"), and their blocks extend
// until the next entry at the same indent or end of the packages section.
func extractPnpmV9PackagePositions(lines []string) map[string]models.FilePosition {
	positions := make(map[string]models.FilePosition)

	inPackages := false
	var currentKey string
	var startLine int

	for i, line := range lines {
		lineNum := i + 1

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// Detect the "packages:" top-level key
		if trimmed == "packages:" {
			inPackages = true

			continue
		}

		if !inPackages {
			continue
		}

		// A line with no leading spaces means we've exited the packages block
		if len(line) > 0 && line[0] != ' ' {
			if currentKey != "" {
				closePnpmBlock(positions, currentKey, i, lines)
				currentKey = ""
			}

			inPackages = false

			continue
		}

		// 2-space indent: package entry (e.g. "  acorn@8.11.3:")
		if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(trimmed, ":") {
			// Close previous package
			if currentKey != "" {
				closePnpmBlock(positions, currentKey, i, lines)
			}

			// Strip trailing ":" and surrounding single quotes (YAML quotes scoped package
			// names starting with "@", e.g. "'@scope/pkg@1.0.0':" → "@scope/pkg@1.0.0").
			pkgKey := strings.Trim(strings.TrimSuffix(trimmed, ":"), "'")
			currentKey = pkgKey
			startLine = lineNum

			colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)

			positions[currentKey] = models.FilePosition{
				Line:   models.Position{Start: startLine, End: 0},
				Column: models.Position{Start: colStart, End: 0},
			}

			continue
		}
	}

	// Close last package if file ended within packages section
	if currentKey != "" {
		pos := positions[currentKey]
		lastIdx := len(lines) - 1
		for lastIdx >= 0 && strings.TrimSpace(lines[lastIdx]) == "" {
			lastIdx--
		}

		if lastIdx >= 0 {
			pos.Line.End = lastIdx + 1
			pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[lastIdx])
		} else {
			pos.Line.End = pos.Line.Start
		}

		positions[currentKey] = pos
	}

	return positions
}

// decodePnpmLockStream decodes every YAML document in the stream and merges
// them into a single PnpmLockfile. pnpm@12 writes pnpm-lock.yaml as a
// multi-document stream: a first document holding packageManagerDependencies
// metadata, followed by a second document holding the real
// importers/packages/snapshots. yaml.Decoder.Decode only consumes one
// document per call, so the stream must be drained in a loop.
func decodePnpmLockStream(r io.Reader, onTypeError func(err error)) (*PnpmLockfile, error) {
	merged := &PnpmLockfile{}
	dec := yaml.NewDecoder(r)

	for {
		var doc PnpmLockfile

		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}

		// A yaml.TypeError is partial: the rest of the document still decoded, so we
		// warn about the skipped entries instead of silently dropping every package.
		var typeErr *yaml.TypeError
		if errors.As(err, &typeErr) {
			if onTypeError != nil {
				onTypeError(typeErr)
			}
		} else if err != nil {
			return merged, err
		}

		mergePnpmLockfile(merged, &doc)
	}

	return merged, nil
}

// mergePnpmImporters unions two PnpmImporters for the same workspace path.
// The env document and project document both key their importer under the
// same workspace path (e.g. "."), each populating different dependency
// groups, so fields must be merged rather than one document's importer
// wholesale replacing the other's.
func mergePnpmImporters(dst, src PnpmImporters) PnpmImporters {
	dst.Dependencies = mergePnpmDependencies(dst.Dependencies, src.Dependencies)
	dst.OptionalDependencies = mergePnpmDependencies(dst.OptionalDependencies, src.OptionalDependencies)
	dst.DevDependencies = mergePnpmDependencies(dst.DevDependencies, src.DevDependencies)
	dst.ConfigDependencies = mergePnpmDependencies(dst.ConfigDependencies, src.ConfigDependencies)

	return dst
}

func mergePnpmDependencies(dst, src PnpmDependencies) PnpmDependencies {
	for name, dep := range src {
		if dst == nil {
			dst = make(PnpmDependencies)
		}
		dst[name] = dep
	}

	return dst
}

// mergePnpmLockfile folds src's fields into dst, keeping whichever document
// in the stream actually populated each field.
func mergePnpmLockfile(dst, src *PnpmLockfile) {
	if src.Version != "" {
		dst.Version = src.Version
	}

	for workspacePath, importer := range src.Importers {
		if dst.Importers == nil {
			dst.Importers = make(map[string]PnpmImporters)
		}
		dst.Importers[workspacePath] = mergePnpmImporters(dst.Importers[workspacePath], importer)
	}

	for key, pkg := range src.Packages {
		if dst.Packages == nil {
			dst.Packages = make(PnpmLockPackages)
		}
		dst.Packages[key] = pkg
	}

	for key, snapshot := range src.Snapshots {
		if dst.Snapshots == nil {
			dst.Snapshots = make(map[string]PnpmSnapshot)
		}
		dst.Snapshots[key] = snapshot
	}
}

func (e PnpmLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	parsedLockfile, err := decodePnpmLockStream(bytes.NewReader(content), func(typeErr error) {
		context.Reporter.Warnf("could not fully decode %s, some entries were skipped: %s\n", f.Path(), typeErr.Error())
	})
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// Check if we need to use the legacy extractor instead
	lockfileVersion, _ := strconv.ParseFloat(strings.ReplaceAll(parsedLockfile.Version, "-flavoured", ""), 32)
	if lockfileVersion < 7.0 {
		file, err := f.Open(f.Path())
		if err != nil {
			return []extractor.PackageDetails{}, err
		}
		defer file.Close()

		return e.extractLegacyPnpm(file)
	}

	lines := fileposition.BytesToLines(content)
	positions := extractPnpmV9PackagePositions(lines)

	return parsePnpmLock(*parsedLockfile, positions, f.Path()), nil
}

var PnpmExtractor = PnpmLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&PackageJSONMatcher{}}},
}

func ParsePnpmLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, PnpmExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.PnpmFilePath, PnpmExtractor)
}
