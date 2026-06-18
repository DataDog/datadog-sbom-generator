package python

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
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
func hasSiblingLockfile(f extractor.DepFile) bool {
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
// PDM is detected via [tool.pdm] or the pdm build backend.
// uv is detected via [tool.uv].
// Everything else is Unknown — [dependency-groups] alone is not sufficient since PEP 735 is tool-agnostic.
func detectPackageManager(pyproject *PyProjectTOML) models.PackageManager {
	if pyproject.Tool.Poetry != nil || strings.Contains(pyproject.BuildSystem.BuildBackend, "poetry") {
		return models.Poetry
	}

	if pyproject.Tool.PDM != nil || strings.Contains(pyproject.BuildSystem.BuildBackend, "pdm") {
		return models.Pdm
	}

	if pyproject.Tool.UV != nil {
		return models.Uv
	}

	return models.Unknown
}

// extractPositions finds the line containing the given rawName and version in lines and returns
// block, name, and version positions. rawName is the pre-normalization name as it appears in the
// file (e.g. "my_pkg"), which may differ from the normalized name used as the package key.
// For PEP 621 string deps the version appears inline; for Poetry key=value deps it is quoted.
func extractPositions(lines []string, filePath, rawName, version string, isPoetry bool) (models.FilePosition, *models.FilePosition, *models.FilePosition) {
	lowerRawName := strings.ToLower(rawName)
	lowerVersion := strings.ToLower(version)

	for i, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(strings.TrimSpace(lowerLine), "#") {
			continue
		}
		if !strings.Contains(lowerLine, lowerRawName) {
			continue
		}
		if version != "" && !strings.Contains(lowerLine, lowerVersion) {
			continue
		}

		lineNumber := i + 1

		nameLocation := fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerRawName, lineNumber)
		if nameLocation == nil {
			continue
		}
		nameLocation.Filename = filePath

		startCol := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		endCol := fileposition.GetLastNonEmptyCharacterIndexInLine(line)
		block := models.FilePosition{
			Line:     models.Position{Start: lineNumber, End: lineNumber},
			Column:   models.Position{Start: startCol, End: endCol},
			Filename: filePath,
		}

		var versionLocation *models.FilePosition
		if version != "" {
			if isPoetry {
				versionLocation = fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, "[^\"']+", lineNumber, "version\\s*=\\s*[\"']", "[\"']")
				if versionLocation == nil {
					versionLocation = fileposition.ExtractDelimitedRegexpPositionInBlock([]string{lowerLine}, "[^\"']+", lineNumber, "=\\s*[\"']", "[\"']")
				}
			} else {
				versionLocation = fileposition.ExtractStringPositionInBlock([]string{lowerLine}, lowerVersion, lineNumber)
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

func (e PyProjectTOMLExtractor) IsManifestParser() bool {
	return true
}

func (e PyProjectTOMLExtractor) PackageManager() models.PackageManager {
	return models.Unknown
}

func (e PyProjectTOMLExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	if hasSiblingLockfile(f) {
		return []extractor.PackageDetails{}, nil
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}

	var pyproject PyProjectTOML
	if err := toml.Unmarshal(content, &pyproject); err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := fileposition.BytesToLines(content)
	pm := detectPackageManager(&pyproject)
	collector := pyprojectPackageCollector{
		packages:       map[string]extractor.PackageDetails{},
		lines:          lines,
		path:           f.Path(),
		packageManager: pm,
		reporter:       reporter.Effective(context.Reporter),
	}

	for _, dep := range pyproject.Project.Dependencies {
		dependency, ok := parsePEP508Dependency(dep)
		if ok {
			collector.addDependency(dependency, []string{string(models.DepGroupProd)}, false)
		}
	}

	for optionalDependencyGroup, deps := range pyproject.Project.OptionalDependencies {
		for _, dep := range deps {
			dependency, ok := parsePEP508Dependency(dep)
			if ok {
				collector.addDependency(dependency, []string{optionalDependencyGroup}, false)
			}
		}
	}

	for dependencyGroupName, dependencyGroupItems := range pyproject.DependencyGroups {
		for _, item := range dependencyGroupItems {
			dep, ok := item.(string)
			if !ok {
				// PEP 735 dependency groups can include table entries such as {include-group = "..."}.
				continue
			}
			dependency, ok := parsePEP508Dependency(dep)
			if ok {
				collector.addDependency(dependency, []string{dependencyGroupName}, false)
			}
		}
	}

	if pyproject.Tool.Poetry != nil {
		for name, val := range pyproject.Tool.Poetry.Dependencies {
			// Poetry uses the "python" key to constrain the interpreter version, not a package dependency
			if name == "python" {
				continue
			}
			if version, versionRange, ok := parsePoetryDependency(val); ok {
				collector.addDependency(pep508Dependency{
					Name:         normalizedRequirementName(name),
					RawName:      name,
					Version:      version,
					VersionRange: versionRange,
				}, []string{string(models.DepGroupProd)}, true)
			}
		}
		for name, val := range pyproject.Tool.Poetry.DevDependencies {
			if version, versionRange, ok := parsePoetryDependency(val); ok {
				collector.addDependency(pep508Dependency{
					Name:         normalizedRequirementName(name),
					RawName:      name,
					Version:      version,
					VersionRange: versionRange,
				}, []string{string(models.DepGroupDev)}, true)
			}
		}
		for poetryGroupName, poetryGroup := range pyproject.Tool.Poetry.Group {
			for name, val := range poetryGroup.Dependencies {
				if version, versionRange, ok := parsePoetryDependency(val); ok {
					collector.addDependency(pep508Dependency{
						Name:         normalizedRequirementName(name),
						RawName:      name,
						Version:      version,
						VersionRange: versionRange,
					}, []string{poetryGroupName}, true)
				}
			}
		}
	}

	return sortedPyprojectPackages(collector.packages), nil
}

type pep508Dependency struct {
	Name         string
	RawName      string
	Version      string
	VersionRange string
}

// parsePEP508Dependency parses a PEP 508 dependency string into a normalized name,
// the raw name as written in the file, and either an exact version or original version range.
func parsePEP508Dependency(dep string) (pep508Dependency, bool) {
	// strip environment markers (PEP 508)
	dep, _, _ = strings.Cut(dep, ";")
	dep = strings.TrimSpace(dep)
	if strings.Contains(dep, " @ ") {
		return pep508Dependency{}, false
	}
	// strip parenthesized specifier: "requests (==2.28.0)" -> "requests ==2.28.0"
	dep = strings.NewReplacer("(", "", ")", "").Replace(dep)

	opIndex, op := findFirstPEP508Specifier(dep)
	if opIndex == -1 || op == "===" {
		return pep508Dependency{}, false
	}

	// strip extras: "requests[security]" -> "requests"
	fileRawName, _, _ := strings.Cut(strings.TrimSpace(dep[:opIndex]), "[")
	fileRawName = strings.TrimSpace(fileRawName)
	specifier := strings.TrimSpace(dep[opIndex:])

	if fileRawName == "" || specifier == "" {
		return pep508Dependency{}, false
	}

	if op == "==" {
		rawVersion := strings.TrimSpace(specifier[len(op):])
		if rawVersion != "" && !strings.Contains(rawVersion, ",") && isConcreteVersion(rawVersion) {
			return pep508Dependency{
				Name:    normalizedRequirementName(fileRawName),
				RawName: fileRawName,
				Version: rawVersion,
			}, true
		}
	}

	return pep508Dependency{
		Name:         normalizedRequirementName(fileRawName),
		RawName:      fileRawName,
		VersionRange: specifier,
	}, true
}

// findFirstPEP508Specifier returns the first PEP 508 version operator in dep.
// Operator order matters because longer operators must be checked before their prefixes.
func findFirstPEP508Specifier(dep string) (int, string) {
	firstIndex := -1
	firstOp := ""
	for _, op := range []string{"===", "==", "!=", ">=", "<=", "~=", ">", "<"} {
		index := strings.Index(dep, op)
		if index == -1 {
			continue
		}
		if firstIndex == -1 || index < firstIndex {
			firstIndex = index
			firstOp = op
		}
	}

	return firstIndex, firstOp
}

// parsePoetryDependency parses a Poetry dependency value (string or inline table) and
// returns either an exact version or the original version range.
func parsePoetryDependency(val any) (version, versionRange string, ok bool) {
	var versionStr string
	switch v := val.(type) {
	case string:
		versionStr = v
	case map[string]any:
		for _, directRefKey := range []string{"path", "git", "url"} {
			if _, exists := v[directRefKey]; exists {
				return "", "", false
			}
		}
		versionStr, ok = v["version"].(string)
		if !ok {
			return "", "", false
		}
	default:
		return "", "", false
	}

	versionStr = strings.TrimSpace(versionStr)
	if versionStr == "" || strings.HasPrefix(versionStr, "===") {
		return "", "", false
	}

	// Poetry bare version string "2.28.0" is an implicit exact pin.
	// Other digit-starting constraints, such as "1.*", are still ranges.
	if len(versionStr) > 0 && !strings.ContainsAny(string(versionStr[0]), "=!<>~^*") {
		if strings.Contains(versionStr, ",") {
			return "", versionStr, true
		}
		if isConcreteVersion(versionStr) {
			return versionStr, "", true
		}

		return "", versionStr, true
	}

	if strings.HasPrefix(versionStr, "==") {
		after := strings.TrimSpace(versionStr[2:])

		if !strings.Contains(after, ",") && isConcreteVersion(after) {
			return after, "", true
		}

		return "", versionStr, true
	}

	return "", versionStr, true
}

// isConcreteVersion returns true if version looks like a fully-specified version
// (no wildcards, no spaces). This guards against patterns like "2.28.*" or "2.28 ".
func isConcreteVersion(version string) bool {
	return version != "" && !strings.Contains(version, "*") && !strings.ContainsAny(version, " \t")
}

// GetArtifact extracts the Python package identity from a pyproject.toml file.
// It returns the [project].name field as the artifact name, using the file's
// own path as Filename so that findArtifact can match packages from sibling
// lockfiles (e.g. requirements.txt) against this module.
func (e PyProjectTOMLExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	if !ctx.ExtractArtifactIds {
		return nil, nil
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var pyproject PyProjectTOML
	if err := toml.Unmarshal(content, &pyproject); err != nil {
		return nil, err
	}

	name := normalizedRequirementName(pyproject.Project.Name)
	if name == "" && pyproject.Tool.Poetry != nil {
		name = normalizedRequirementName(pyproject.Tool.Poetry.Name)
	}
	if name == "" {
		return nil, nil
	}

	return &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      name,
			Filename:  f.Path(),
			Ecosystem: models.EcosystemPyPI,
		},
	}, nil
}

var PyProjectExtractor = PyProjectTOMLExtractor{}

func ParsePyProjectTOML(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, PyProjectExtractor)
}

var _ extractor.Extractor = PyProjectExtractor
var _ extractor.ManifestExtractor = PyProjectExtractor
var _ extractor.ArtifactExtractor = PyProjectExtractor

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.PyProjectTomlFilePath, PyProjectExtractor)
}
