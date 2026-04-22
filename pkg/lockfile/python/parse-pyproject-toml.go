package python

import (
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

var pyprojectSiblingLockfiles = []string{
	models.PoetryFilePath.String(),
	models.PdmFilePath.String(),
	models.UvFilePath.String(),
	models.PipfileFilePath.String(),
}

// hasSiblingLockfile returns true if any known Python lock file exists in the same directory as f.
// The check is unconditional — regardless of which parsers are enabled — because a sibling lock
// file always describes this project more accurately than a manifest-derived scan.
// Ancestor directories are intentionally not checked: an ancestor lock file does not describe a nested project.
func hasSiblingLockfile(f lockfile.DepFile) bool {
	for _, name := range pyprojectSiblingLockfiles {
		if sibling, err := f.Open(name); err == nil {
			sibling.Close()
			return true
		}
	}

	return false
}

// detectPackageManager determines the package manager from the parsed pyproject.toml content.
// Poetry is detected via [tool.poetry] or the poetry build backend.
// PDM is detected via [tool.pdm].
// uv is detected via [tool.uv].
// Everything else is Unknown — [dependency-groups] alone is not sufficient since PEP 735 is tool-agnostic.
func detectPackageManager(pyproject *PyProjectTOML) models.PackageManager {
	if pyproject.Tool.Poetry != nil || strings.Contains(pyproject.BuildSystem.BuildBackend, "poetry") {
		return models.Poetry
	}

	if pyproject.Tool.PDM != nil {
		return models.Pdm
	}

	if pyproject.Tool.UV != nil {
		return models.Uv
	}

	return models.Unknown
}

// extractPositions finds the line containing the given name in lines and returns
// block, name, and version positions. For PEP 621 string deps the version appears
// inline; for Poetry key=value deps the version is in a quoted value.
func extractPositions(lines []string, filePath, name, version string, isPoetry bool) (models.FilePosition, *models.FilePosition, *models.FilePosition) {
	lowerName := strings.ToLower(name)

	for i, line := range lines {
		if !strings.Contains(strings.ToLower(line), lowerName) {
			continue
		}

		lineNumber := i + 1
		startCol := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		endCol := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

		block := models.FilePosition{
			Line:     models.Position{Start: lineNumber, End: lineNumber},
			Column:   models.Position{Start: startCol, End: endCol},
			Filename: filePath,
		}

		nameLocation := fileposition.ExtractStringPositionInBlock([]string{line}, lowerName, lineNumber)
		if nameLocation != nil {
			nameLocation.Filename = filePath
		}

		var versionLocation *models.FilePosition
		if version != "" {
			if isPoetry {
				versionLocation = fileposition.ExtractDelimitedRegexpPositionInBlock([]string{line}, ".*", lineNumber, "=\\s*\"", "\"")
			} else {
				versionLocation = fileposition.ExtractStringPositionInBlock([]string{line}, version, lineNumber)
			}
			if versionLocation != nil {
				versionLocation.Filename = filePath
			}
		}

		return block, nameLocation, versionLocation
	}

	return models.FilePosition{Filename: filePath}, nil, nil
}

func (e PyProjectTOMLExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PyProjectTomlFilePath.String()
}

func (e PyProjectTOMLExtractor) IsOfficiallySupported() bool {
	return pyprojectOfficiallySupported
}

func (e PyProjectTOMLExtractor) IsNoLockfileParser() bool {
	return true
}

func (e PyProjectTOMLExtractor) PackageManager() models.PackageManager {
	return models.Uv
}

func (e PyProjectTOMLExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	if hasSiblingLockfile(f) {
		return []lockfile.PackageDetails{}, nil
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}

	var pyproject PyProjectTOML
	if err := toml.Unmarshal(content, &pyproject); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := fileposition.BytesToLines(content)
	pm := detectPackageManager(&pyproject)
	packages := map[string]lockfile.PackageDetails{}

	for _, dep := range pyproject.Project.Dependencies {
		if name, version, ok := parsePEP508Pin(dep); ok {
			block, nameLocation, versionLocation := extractPositions(lines, f.Path(), name, version, false)
			addOrMergeGroups(packages, name, version, []string{"prod"}, pm, block, nameLocation, versionLocation)
		}
	}

	for group, deps := range pyproject.Project.OptionalDependencies {
		for _, dep := range deps {
			if name, version, ok := parsePEP508Pin(dep); ok {
				block, nameLocation, versionLocation := extractPositions(lines, f.Path(), name, version, false)
				addOrMergeGroups(packages, name, version, []string{group}, pm, block, nameLocation, versionLocation)
			}
		}
	}

	for group, items := range pyproject.DependencyGroups {
		for _, item := range items {
			dep, ok := item.(string)
			if !ok {
				// skip {include-group = "..."} table entries
				continue
			}
			if name, version, ok := parsePEP508Pin(dep); ok {
				block, nameLocation, versionLocation := extractPositions(lines, f.Path(), name, version, false)
				addOrMergeGroups(packages, name, version, []string{group}, pm, block, nameLocation, versionLocation)
			}
		}
	}

	if pyproject.Tool.Poetry != nil {
		for name, val := range pyproject.Tool.Poetry.Dependencies {
			// Poetry uses the "python" key to constrain the interpreter version, not a package dependency
			if name == "python" {
				continue
			}
			if version, ok := parsePoetryPin(val); ok {
				normalized := normalizedRequirementName(name)
				block, nameLocation, versionLocation := extractPositions(lines, f.Path(), normalized, version, true)
				addOrMergeGroups(packages, normalized, version, []string{"prod"}, pm, block, nameLocation, versionLocation)
			}
		}
		for name, val := range pyproject.Tool.Poetry.DevDependencies {
			if version, ok := parsePoetryPin(val); ok {
				normalized := normalizedRequirementName(name)
				block, nameLocation, versionLocation := extractPositions(lines, f.Path(), normalized, version, true)
				addOrMergeGroups(packages, normalized, version, []string{"dev"}, pm, block, nameLocation, versionLocation)
			}
		}
		for groupName, group := range pyproject.Tool.Poetry.Group {
			for name, val := range group.Dependencies {
				if version, ok := parsePoetryPin(val); ok {
					normalized := normalizedRequirementName(name)
					block, nameLocation, versionLocation := extractPositions(lines, f.Path(), normalized, version, true)
					addOrMergeGroups(packages, normalized, version, []string{groupName}, pm, block, nameLocation, versionLocation)
				}
			}
		}
	}

	return slices.Collect(maps.Values(packages)), nil
}

// addOrMergeGroups adds a package to the map, or if it already exists (same name+version),
// merges the new dep groups into the existing entry rather than dropping the duplicate.
func addOrMergeGroups(packages map[string]lockfile.PackageDetails, name, version string, groups []string, pm models.PackageManager, block models.FilePosition, nameLocation, versionLocation *models.FilePosition) {
	key := name + "@" + version
	if existing, exists := packages[key]; exists {
		for _, g := range groups {
			if !slices.Contains(existing.DepGroups, g) {
				existing.DepGroups = append(existing.DepGroups, g)
			}
		}
		packages[key] = existing

		return
	}
	packages[key] = lockfile.PackageDetails{
		Name:            name,
		Version:         version,
		PackageManager:  pm,
		Ecosystem:       models.EcosystemPyPI,
		IsDirect:        true,
		DepGroups:       groups,
		BlockLocation:   block,
		NameLocation:    nameLocation,
		VersionLocation: versionLocation,
	}
}

// parsePEP508Pin parses a PEP 508 dependency string and returns the normalized name and version
// only when the dependency is an exact pin (==). Returns ok=false for all other specifiers.
func parsePEP508Pin(dep string) (name, version string, ok bool) {
	// strip environment markers (PEP 508)
	dep, _, _ = strings.Cut(dep, ";")
	dep = strings.TrimSpace(dep)

	// Find the == operator and ensure it is a standalone exact-pin, not part of
	// !=, >=, <=, ~= (checked via the preceding character) or === (checked via the following character).
	idx := strings.Index(dep, "==")
	if idx < 0 {
		return "", "", false
	}
	if idx > 0 {
		if prev := dep[idx-1]; prev == '!' || prev == '>' || prev == '<' || prev == '~' {
			return "", "", false
		}
	}
	if idx+2 < len(dep) && dep[idx+2] == '=' {
		return "", "", false
	}
	// reject multi-constraint specs where == appears after another constraint e.g. "requests~=2.28,==2.28.0"
	if strings.Contains(dep[:idx], ",") {
		return "", "", false
	}

	// strip optional parenthesis: "requests (" -> "requests"
	rawName := strings.TrimRight(strings.TrimSpace(dep[:idx]), "( ")
	rawVersion := strings.TrimSpace(dep[idx+2:])

	// strip extras: requests[security] -> requests
	rawName, _, _ = strings.Cut(rawName, "[")
	rawName = strings.TrimSpace(rawName)

	// reject multi-constraint specs like "==2.28.0,!=2.28.0" — not an exact pin
	if strings.Contains(rawVersion, ",") {
		return "", "", false
	}
	rawVersion = strings.TrimSpace(strings.TrimRight(rawVersion, ")"))

	if rawName == "" || rawVersion == "" || !isConcreteVersion(rawVersion) {
		return "", "", false
	}

	return normalizedRequirementName(rawName), rawVersion, true
}

// parsePoetryPin parses a Poetry dependency value (string or inline table) and returns
// the version only when it is an exact pin (== prefix) with a concrete version.
func parsePoetryPin(val any) (version string, ok bool) {
	var versionStr string
	switch v := val.(type) {
	case string:
		versionStr = v
	case map[string]any:
		versionStr, ok = v["version"].(string)
		if !ok {
			return "", false
		}
	default:
		return "", false
	}

	versionStr = strings.TrimSpace(versionStr)

	// Poetry bare version string "2.28.0" is an implicit exact pin
	if len(versionStr) > 0 && !strings.ContainsAny(string(versionStr[0]), "=!<>~^*") {
		if strings.Contains(versionStr, ",") {
			return "", false
		}
		if isConcreteVersion(versionStr) {
			return versionStr, true
		}

		return "", false
	}

	// reject === (arbitrary equality) and any non-== operator
	if !strings.HasPrefix(versionStr, "==") || strings.HasPrefix(versionStr, "===") {
		return "", false
	}

	after := strings.TrimSpace(versionStr[2:])

	// reject multi-constraint: "==2.28.0,!=2.28.1" is not an exact pin
	if strings.Contains(after, ",") {
		return "", false
	}

	if isConcreteVersion(after) {
		return after, true
	}

	return "", false
}

// isConcreteVersion returns true if version looks like a fully-specified version
// (no wildcards, no spaces). This guards against patterns like "2.28.*" or "2.28 ".
func isConcreteVersion(version string) bool {
	return version != "" && !strings.Contains(version, "*") && !strings.ContainsAny(version, " \t")
}

var PyProjectExtractor = PyProjectTOMLExtractor{}

func ParsePyProjectTOML(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PyProjectExtractor)
}

var _ lockfile.Extractor = PyProjectExtractor
var _ lockfile.NoLockfileExtractor = PyProjectExtractor

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PyProjectTomlFilePath, PyProjectExtractor)
}
