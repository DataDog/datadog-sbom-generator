package javascript

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

func startsWithNumber(str string) bool {
	matcher := cachedregexp.MustCompile(`^\d`)

	return matcher.MatchString(str)
}

// extractPnpmPackageNameAndVersion parses a dependency path, attempting to
// extract the name and version of the package it represents
func extractPnpmPackageNameAndVersion(dependencyPath string) (string, string) {
	// file dependencies must always have a name property to be installed,
	// and their dependency path never has the version encoded, so we can
	// skip trying to extract either from their dependency path
	if strings.HasPrefix(dependencyPath, "file:") {
		return "", ""
	}

	parts := strings.Split(dependencyPath, "/")
	var name string

	parts = parts[1:]

	if len(parts) == 0 {
		// Seems path is not complete (or at least the version is not in the path)
		// TODO : Investigate when it can happen, this is to stabilize the situation
		return "", ""
	}

	if strings.HasPrefix(parts[0], "@") {
		name = strings.Join(parts[:2], "/")
		parts = parts[2:]
	} else {
		name = parts[0]
		parts = parts[1:]
	}

	version := ""

	if len(parts) != 0 {
		version = parts[0]
	}

	if version == "" {
		name, version = parseNameAtVersion(name)
	}

	if version == "" || !startsWithNumber(version) {
		return "", ""
	}

	underscoreIndex := strings.Index(version, "_")

	if underscoreIndex != -1 {
		version = strings.Split(version, "_")[0]
	}

	return name, version
}

func parseNameAtVersion(value string) (name string, version string) {
	// look for pattern "name@version", where name is allowed to contain zero or more "@"
	matches := cachedregexp.MustCompile(`^(.+)@([\d.]+)$`).FindStringSubmatch(value)

	if len(matches) != 3 {
		return name, ""
	}

	return matches[1], matches[2]
}

func sanitizeLocalDependencyPath(value string, prefix string) string {
	if strings.HasPrefix(value, prefix+":") {
		value = strings.TrimPrefix(value, prefix+":")
		// Current dir locations may include an initial './'
		return strings.TrimPrefix(value, "./")
	}

	return value
}

func getVersionInfo(name string, maps ...map[string]PnpmLegacyLockDependency) (specifier, version string, found bool) {
	for _, m := range maps {
		if info, ok := m[name]; ok {
			return info.Specifier, info.Version, true
		}
	}

	return "", "", false
}

// extractPnpmLegacyPackagePositions scans YAML lines for package entries under "packages:".
// Legacy pnpm package keys appear at 2-space indent (e.g. "  /acorn/8.7.0:").
func extractPnpmLegacyPackagePositions(lines []string) map[string]models.FilePosition {
	positions := make(map[string]models.FilePosition)

	inPackages := false
	var currentKey string

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

		// 2-space indent: package entry (e.g. "  /acorn/8.7.0:")
		if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(trimmed, ":") {
			// Close previous package
			if currentKey != "" {
				closePnpmBlock(positions, currentKey, i, lines)
			}

			pkgKey := strings.TrimSuffix(trimmed, ":")
			currentKey = pkgKey

			colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)

			positions[currentKey] = models.FilePosition{
				Line:   models.Position{Start: lineNum, End: 0},
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

func parsePnpmLegacyLock(sourceFile PnpmLegacyLockfile, positions map[string]models.FilePosition, filePath string) []lockfile.PackageDetails {
	packages := make([]lockfile.PackageDetails, 0, len(sourceFile.Packages))

	for s, pkg := range sourceFile.Packages {
		name, version := extractPnpmPackageNameAndVersion(s)

		// Extract right part of key to then match the specifier
		var lastIndex int
		lockfileVersion, _ := strconv.ParseFloat(strings.ReplaceAll(sourceFile.Version, "-flavoured", ""), 32)
		if lockfileVersion >= 6.0 {
			lastIndex = strings.LastIndex(s, "@")
		} else {
			lastIndex = strings.LastIndex(s, "/")
		}
		right := s[lastIndex+1:]

		// "name" is only present if it's not in the dependency path and takes
		// priority over whatever name we think we've extracted (if any)
		if pkg.Name != "" {
			name = pkg.Name
		}

		// "version" is only present if it's not in the dependency path and takes
		// priority over whatever version we think we've extracted (if any)
		if pkg.Version != "" {
			version = pkg.Version
		}

		if name == "" || version == "" {
			continue
		}

		commit := pkg.Resolution.Commit

		if strings.HasPrefix(pkg.Resolution.Tarball, "https://codeload.github.com") {
			re := cachedregexp.MustCompile(`https://codeload\.github\.com(?:/[\w-.]+){2}/tar\.gz/(\w+)$`)
			matched := re.FindStringSubmatch(pkg.Resolution.Tarball)

			if matched != nil {
				commit = matched[1]
			}
		}

		var depGroups []string
		if pkg.Dev {
			depGroups = append(depGroups, "dev")
		}

		var targetVersions []string
		var targetVersion string
		var dependencyVersion string
		var isDirect bool

		// Find target and dependency version
		if sp, ok := sourceFile.Specifiers[name]; ok {
			// lockfile version <6.0
			targetVersion = sp
			dependencyVersion = ""
			if _, v, f := getVersionInfo(name, sourceFile.Dependencies, sourceFile.DevDependencies, sourceFile.OptionalDependencies); f {
				isDirect = true
				dependencyVersion = v
			}
		} else if sp, v, f := getVersionInfo(name, sourceFile.Dependencies, sourceFile.DevDependencies, sourceFile.OptionalDependencies); f {
			// lockfile version >6.0
			targetVersion = sp
			dependencyVersion = v
			isDirect = true
		}

		// Sanitize the target/dependency version
		prefixes := []string{"file", "link", "portal"}
		for _, prefix := range prefixes {
			targetVersion = sanitizeLocalDependencyPath(targetVersion, prefix)
			dependencyVersion = sanitizeLocalDependencyPath(dependencyVersion, prefix)
		}

		// Multiple versions of the same dependency -> We want to set the
		// target versions only for the one included in the dependencies map
		if strings.Contains(dependencyVersion, right) {
			targetVersions = []string{targetVersion}
		}

		blockLocation := models.FilePosition{}
		if pos, ok := positions[s]; ok {
			pos.Filename = filePath
			blockLocation = pos
		}

		packages = append(packages, lockfile.PackageDetails{
			Name:           name,
			Version:        version,
			TargetVersions: targetVersions,
			PackageManager: pnpmPackageManager,
			Ecosystem:      models.EcosystemNPM,
			Commit:         commit,
			DepGroups:      depGroups,
			IsDirect:       isDirect,
			BlockLocation:  blockLocation,
		})
	}

	return packages
}

func (e PnpmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PnpmFilePath.String()
}

func (e PnpmLockExtractor) IsOfficiallySupported() bool {
	return pnpmOfficiallySupported
}

func (e PnpmLockExtractor) PackageManager() models.PackageManager {
	return pnpmPackageManager
}

func (e PnpmLockExtractor) extractLegacyPnpm(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PnpmLegacyLockfile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = yaml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// this will happen if the file is empty
	if parsedLockfile == nil {
		parsedLockfile = &PnpmLegacyLockfile{}
	}

	lines := fileposition.BytesToLines(content)
	positions := extractPnpmLegacyPackagePositions(lines)

	return parsePnpmLegacyLock(*parsedLockfile, positions, f.Path()), nil
}
