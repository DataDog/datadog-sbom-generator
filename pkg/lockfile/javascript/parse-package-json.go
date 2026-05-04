package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	jsonUtils "github.com/DataDog/datadog-sbom-generator/internal/json"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

var siblingLockfiles = []string{
	"package-lock.json",
	"yarn.lock",
	"pnpm-lock.yaml",
}

func activeLockfiles(enabledParsers map[string]bool) []string {
	var active []string
	for _, name := range siblingLockfiles {
		if len(enabledParsers) == 0 || enabledParsers[name] {
			active = append(active, name)
		}
	}

	return active
}

func hasLockfileInAncestors(f lockfile.DepFile, rootDir string, lockfiles []string) bool {
	for _, name := range lockfiles {
		sibling, err := f.Open(name)
		if err == nil {
			sibling.Close()

			return true
		}
	}

	if rootDir == "" {
		return false
	}

	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return false
	}

	rootDir = filepath.Clean(absRoot)
	fileDir := filepath.Dir(f.Path())
	dir := filepath.Dir(fileDir)

	for {
		if !strings.HasPrefix(dir, rootDir) {
			break
		}

		for _, name := range lockfiles {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return true
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}

		dir = parent
	}

	return false
}

var versionTokenRegex = cachedregexp.MustCompile(`^[~^>=<]*\s*v?\d[\w.*-]*`)
var exactVersionRegex = cachedregexp.MustCompile(`^v?\d+(\.\d+)*(-[\w.]+)?(\+[\w.]+)?$`)

func isExactVersion(specifier string) bool {
	return exactVersionRegex.MatchString(specifier)
}

func effectiveVersionSpecifier(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	if strings.HasPrefix(specifier, "npm:") {
		idx := strings.LastIndex(specifier, "@")
		if idx > 4 {
			return strings.TrimSpace(specifier[idx+1:])
		}

		return ""
	}

	if strings.Contains(specifier, "/") {
		return ""
	}

	// Strip standalone = operator (npm exact pin: =1.2.3 ≡ 1.2.3)
	if strings.HasPrefix(specifier, "=") && !strings.HasPrefix(specifier, ">=") {
		specifier = specifier[1:]
	}

	return specifier
}

func ResolveNpmAlias(specifier string) string {
	specifier = strings.TrimSpace(specifier)
	if !strings.HasPrefix(specifier, "npm:") {
		return ""
	}

	idx := strings.LastIndex(specifier, "@")
	if idx > 4 {
		return specifier[4:idx]
	}

	return specifier[4:]
}

func hasVersionToken(specifier string) bool {
	for _, field := range strings.Fields(specifier) {
		if versionTokenRegex.MatchString(field) {
			return true
		}
	}

	return false
}

type packageJSONRaw struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (e PackageJSONExtractor) ShouldExtract(path string) bool {
	normalized := filepath.ToSlash(path)
	if strings.Contains(normalized, "/"+nodeModulesPath) || strings.HasPrefix(normalized, nodeModulesPath) {
		return false
	}

	return filepath.Base(path) == models.PackageJSONFilePath.String()
}

func (e PackageJSONExtractor) IsOfficiallySupported() bool {
	return packageJSONOfficiallySupported
}

func (e PackageJSONExtractor) PackageManager() models.PackageManager {
	return packageJSONPackageManager
}

func computeFilePosition(contentStr string, filePath string, startIdx int, endIdx int) models.FilePosition {
	lineStart := strings.Count(contentStr[:startIdx], "\n")
	lineStartIndex := strings.LastIndex(contentStr[:startIdx], "\n")
	lineEnd := strings.Count(contentStr[:endIdx], "\n")
	lineEndIndex := strings.LastIndex(contentStr[:endIdx], "\n")

	return models.FilePosition{
		Filename: filePath,
		Line: models.Position{
			Start: lineStart + 1,
			End:   lineEnd + 1,
		},
		Column: models.Position{
			Start: startIdx - lineStartIndex,
			End:   endIdx - lineEndIndex,
		},
	}
}

func (e PackageJSONExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	lockfiles := activeLockfiles(context.EnabledParsers)
	if len(lockfiles) > 0 && hasLockfileInAncestors(f, context.RootDir, lockfiles) {
		return []lockfile.PackageDetails{}, nil
	}

	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read from %s: %w", f.Path(), err)
	}

	var raw packageJSONRaw
	if err := json.Unmarshal(contentBytes, &raw); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	contentStr := string(contentBytes)

	packages := make(map[string]lockfile.PackageDetails)

	type depSection struct {
		deps  map[string]string
		group string
	}

	sections := []depSection{
		{deps: raw.Dependencies, group: "prod"},
		{deps: raw.DevDependencies, group: "dev"},
		{deps: raw.OptionalDependencies, group: "optional"},
	}

	for _, section := range sections {
		// Sort alias names so that when multiple aliases resolve to the same package
		// with different ranges, the alphabetically-first alias key always wins.
		names := make([]string, 0, len(section.deps))
		for name := range section.deps {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			specifier := section.deps[name]
			resolvedName := name
			if alias := ResolveNpmAlias(specifier); alias != "" {
				resolvedName = alias
			}

			effectiveSpec := effectiveVersionSpecifier(specifier)
			var version, versionRange string
			switch {
			case isExactVersion(effectiveSpec):
				version = effectiveSpec
			case hasVersionToken(effectiveSpec):
				versionRange = effectiveSpec
			}

			// Exact-version entries are keyed by name@version (one entry per version).
			// Range and no-version entries share a key by name alone: if multiple aliases
			// resolve to the same package at different ranges, the alphabetically-first
			// alias name wins and subsequent ones are dropped.
			dedupKey := resolvedName
			if version != "" {
				dedupKey = resolvedName + "@" + version
			}

			if _, exists := packages[dedupKey]; exists {
				continue
			}

			blockLocation := models.FilePosition{Filename: f.Path()}
			var nameLocation *models.FilePosition
			var versionLocation *models.FilePosition

			pkgIndexes := jsonUtils.ExtractPackageIndexes(name, specifier, contentStr)
			if len(pkgIndexes) >= 6 {
				blockLocation = computeFilePosition(contentStr, f.Path(), pkgIndexes[0], pkgIndexes[1])

				nl := computeFilePosition(contentStr, f.Path(), pkgIndexes[2], pkgIndexes[3])
				nameLocation = &nl

				vl := computeFilePosition(contentStr, f.Path(), pkgIndexes[4], pkgIndexes[5])
				versionLocation = &vl
			}

			packages[dedupKey] = lockfile.PackageDetails{
				Name:            resolvedName,
				Version:         version,
				VersionRange:    versionRange,
				PackageManager:  packageJSONPackageManager,
				Ecosystem:       models.EcosystemNPM,
				IsDirect:        true,
				DepGroups:       []string{section.group},
				BlockLocation:   blockLocation,
				NameLocation:    nameLocation,
				VersionLocation: versionLocation,
			}
		}
	}

	result := make([]lockfile.PackageDetails, 0, len(packages))
	for _, pkg := range packages {
		result = append(result, pkg)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		if result[i].Version != result[j].Version {
			return result[i].Version < result[j].Version
		}

		return result[i].VersionRange < result[j].VersionRange
	})

	return result, nil
}

var packageJSONExtractor = PackageJSONExtractor{}

func ParsePackageJSON(path string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(path, packageJSONExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PackageJSONFilePath, packageJSONExtractor)
}
