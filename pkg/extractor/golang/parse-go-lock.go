package golang

import (
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

func deduplicatePackages(packages map[string]extractor.PackageDetails) map[string]extractor.PackageDetails {
	details := map[string]extractor.PackageDetails{}

	for _, detail := range packages {
		details[detail.Name+"@"+detail.Version] = detail
	}

	return details
}

func defaultNonCanonicalVersions(path, version string) (string, error) {
	resolvedVersion := module.CanonicalVersion(version)

	// If the resolvedVersion is not canonical, we try to find the major resolvedVersion in the path and report that
	if resolvedVersion == "" {
		_, pathMajor, ok := module.SplitPathVersion(path)
		if ok {
			resolvedVersion = module.PathMajorPrefix(pathMajor)
		}
	}

	if resolvedVersion == "" {
		return unknownVersion, nil
	}

	return resolvedVersion, nil
}

func extractLocations(block []string, start modfile.Position, end modfile.Position, path string, name string, version string) (models.FilePosition, *models.FilePosition, *models.FilePosition) {
	blockLocation := models.FilePosition{
		Line:     models.Position{Start: start.Line, End: end.Line},
		Column:   models.Position{Start: start.LineRune, End: end.LineRune},
		Filename: path,
	}

	nameLocation := fileposition.ExtractStringPositionInBlock(block, name, start.Line)
	if nameLocation != nil {
		nameLocation.Filename = path
	}

	versionLocation := fileposition.ExtractStringPositionInBlock(block, version, start.Line)
	if versionLocation != nil {
		versionLocation.Filename = path
	}

	return blockLocation, nameLocation, versionLocation
}

func (e GoLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.GolangFilePath.String()
}

func (e GoLockExtractor) IsOfficiallySupported() bool {
	return goOfficiallySupported
}

func (e GoLockExtractor) PackageManager() models.PackageManager {
	return goPackageManager
}

func (e GoLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *modfile.File

	b, err := io.ReadAll(f)
	lines := fileposition.BytesToLines(b)

	if err == nil {
		parsedLockfile, err = modfile.Parse(f.Path(), b, defaultNonCanonicalVersions)
	}

	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	packages := map[string]extractor.PackageDetails{}

	for _, require := range parsedLockfile.Require {
		var start = require.Syntax.Start
		var end = require.Syntax.End
		block := lines[start.Line-1 : end.Line]
		name := require.Mod.Path
		version := strings.TrimPrefix(require.Mod.Version, "v")

		if require.Mod.Version == unknownVersion {
			version = ""
		}

		blockLocation, nameLocation, versionLocation := extractLocations(block, start, end, f.Path(), name, version)
		packages[require.Mod.Path+"@"+require.Mod.Version] = extractor.PackageDetails{
			Name:            name,
			Version:         version,
			PackageManager:  goPackageManager,
			Ecosystem:       models.EcosystemGo,
			BlockLocation:   blockLocation,
			LocationRole:    models.LocationRoleManifest,
			NameLocation:    nameLocation,
			VersionLocation: versionLocation,
			IsDirect:        !require.Indirect,
		}
	}

	for _, replace := range parsedLockfile.Replace {
		var start = replace.Syntax.Start
		var end = replace.Syntax.End
		block := lines[start.Line-1 : end.Line]
		var replacements []string

		isLocalFile := !hasHostnamePrefix(replace.New.Path)

		if replace.Old.Version == "" {
			// If the left version is omitted, all versions of the module are replaced.
			for k, pkg := range packages {
				if pkg.Name == replace.Old.Path {
					replacements = append(replacements, k)
				}
			}
		} else {
			// If a version is present on the left side of the arrow (=>),
			// only that specific version of the module is replaced
			s := replace.Old.Path + "@" + replace.Old.Version

			// A `replace` directive has no effect if the module version on the left side is not required.
			if _, ok := packages[s]; ok {
				replacements = []string{s}
			}
		}

		for _, replacement := range replacements {
			version := strings.TrimPrefix(replace.New.Version, "v")
			name := replace.New.Path

			if replace.New.Version == unknownVersion {
				// If it is still not resolved, we default on 0.0.0 as we do with other package managers
				context.Reporter.Warnf("%s@%s is not a canonical path, defaulting to %s\n", replace.Old.Path, replace.Old.Version, version)
				version = ""
			}

			blockLocation, nameLocation, versionLocation := extractLocations(block, start, end, f.Path(), name, version)

			if isLocalFile {
				// The replacement is a local file path, we keep the original package name and drop everything specific to the replacement
				name = replace.Old.Path
				version = ""
				versionLocation = nil
				nameLocation = nil
			}

			packages[replacement] = extractor.PackageDetails{
				Name:            name,
				Version:         version,
				PackageManager:  goPackageManager,
				Ecosystem:       models.EcosystemGo,
				BlockLocation:   blockLocation,
				LocationRole:    models.LocationRoleManifest,
				VersionLocation: versionLocation,
				NameLocation:    nameLocation,
				IsDirect:        packages[replacement].IsDirect,
			}
		}
	}

	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		start := parsedLockfile.Go.Syntax.Start
		end := parsedLockfile.Go.Syntax.End
		block := lines[start.Line-1 : end.Line]
		blockLocation, nameLocation, versionLocation := extractLocations(block, start, end, f.Path(), "go", parsedLockfile.Go.Version)

		packages["stdlib"] = extractor.PackageDetails{
			Name:            "stdlib",
			Version:         parsedLockfile.Go.Version,
			PackageManager:  goPackageManager,
			Ecosystem:       models.EcosystemGo,
			BlockLocation:   blockLocation,
			LocationRole:    models.LocationRoleManifest,
			NameLocation:    nameLocation,
			VersionLocation: versionLocation,
			IsDirect:        true,
		}
	}

	return slices.Collect(maps.Values(deduplicatePackages(packages))), nil
}

func hasHostnamePrefix(path string) bool {
	matcher := cachedregexp.MustCompile("^(\\w+:\\/\\/)?\\w+\\.\\w+.*")

	return matcher.MatchString(path)
}

// GetArtifact implements extractor.ArtifactExtractor.
// It parses the go.mod file to extract the module name and discovers internal
// project dependencies via local-path replace directives.
func (e GoLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	b, err := io.ReadAll(f)
	if err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	parsedLockfile, err := modfile.Parse(f.Path(), b, defaultNonCanonicalVersions)
	if err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	var moduleName string
	if parsedLockfile.Module != nil {
		moduleName = parsedLockfile.Module.Mod.Path
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			PackageName: moduleName,
			Filename:    f.Path(),
			Ecosystem:   models.EcosystemGo,
		},
	}

	// Build the set of required module keys so we only follow replace
	// directives that are actually selected by the module graph — matching
	// the filtering logic already used in Extract(). For version-specific
	// replaces (replace.Old.Version != ""), we key by "path@version" so that
	// a replace for v2.0.0 is not emitted when only v1.0.0 is required.
	required := make(map[string]struct{}, len(parsedLockfile.Require))
	for _, req := range parsedLockfile.Require {
		required[req.Mod.Path] = struct{}{}
		required[req.Mod.Path+"@"+req.Mod.Version] = struct{}{}
	}

	seen := make(map[string]struct{})
	goModDir := filepath.Dir(f.Path())

	for _, replace := range parsedLockfile.Replace {
		if hasHostnamePrefix(replace.New.Path) {
			continue
		}

		// Per the Go spec, a replacement with a version on the right-hand side
		// (replace old => new v1.2.3) is always a module path, never a local
		// directory. Only version-less replacements can point to a local path.
		if replace.New.Version != "" {
			continue
		}

		// Use the versioned key when the replace targets a specific version,
		// otherwise fall back to the unversioned path — same logic as Extract().
		requireKey := replace.Old.Path
		if replace.Old.Version != "" {
			requireKey = replace.Old.Path + "@" + replace.Old.Version
		}

		if _, ok := required[requireKey]; !ok {
			continue
		}

		var targetDir string
		if filepath.IsAbs(replace.New.Path) {
			targetDir = replace.New.Path
		} else {
			targetDir = filepath.Join(goModDir, replace.New.Path)
		}
		targetGoMod := filepath.Clean(filepath.Join(targetDir, "go.mod"))

		if _, err := os.Stat(targetGoMod); err != nil {
			continue
		}

		// Skip targets outside the scan root: they were never walked by the
		// scanner, so emitting them would produce dangling BOM references.
		// Normalize ctx.RootDir to an absolute path first — filepath.Rel
		// returns an error for mixed relative/absolute inputs (e.g. "." vs
		// "/abs/path"), which would incorrectly skip all valid replace edges.
		if ctx.RootDir != "" {
			absRoot, err := filepath.Abs(ctx.RootDir)
			if err == nil {
				rel, err := filepath.Rel(absRoot, targetGoMod)
				if err != nil || strings.HasPrefix(rel, "..") {
					continue
				}
			}
		}

		if _, ok := seen[targetGoMod]; ok {
			continue
		}
		seen[targetGoMod] = struct{}{}

		artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
			Filename: targetGoMod,
		})
	}

	return artifact, nil
}

var _ extractor.ArtifactExtractor = GoLockExtractor{}
var _ extractor.Extractor = GoLockExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.GolangFilePath, GoLockExtractor{})
}

func ParseGoLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, GoLockExtractor{})
}
