package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/tidwall/jsonc"
)

func (e BunLockExtractor) ShouldExtract(path string) bool {
	if filepath.Base(path) != models.BunFilePath.String() {
		return false
	}
	// Skip lockfiles nested in node_modules — they belong to a dependency, not the project.
	dir := filepath.ToSlash(filepath.Dir(path))

	return !strings.Contains("/"+dir+"/", "/node_modules/")
}

func (e BunLockExtractor) IsOfficiallySupported() bool {
	return bunOfficiallySupported
}

func (e BunLockExtractor) PackageManager() models.PackageManager {
	return bunPackageManager
}

// Adapted from github.com/google/osv-scalibr@ec4239d (Apache-2.0).
// https://github.com/google/osv-scalibr/blob/ec4239d68fb9375123197cf1e37de296061b9e57/extractor/filesystem/language/javascript/bunlock/bunlock.go
func structureBunPackageDetails(tuple []json.RawMessage) (string, string, string, error) {
	if len(tuple) == 0 {
		return "", "", "", errors.New("empty package tuple")
	}

	var str string
	if err := json.Unmarshal(tuple[0], &str); err != nil {
		return "", "", "", errors.New("first element of package tuple is not a string")
	}

	str, isScoped := strings.CutPrefix(str, "@")
	name, version, _ := strings.Cut(str, "@")
	if isScoped {
		name = "@" + name
	}

	version, commit, _ := strings.Cut(version, "#")
	if commit != "" {
		version = ""
	}
	if strings.HasPrefix(version, "file:") {
		version = ""
	}

	return name, version, commit, nil
}

func collectBunTargetVersions(workspaces map[string]BunLockWorkspace, name string) []string {
	seen := make(map[string]bool)
	targetVersions := make([]string, 0)

	for _, workspace := range workspaces {
		targetVersions = appendBunTargetVersion(targetVersions, seen, workspace.Dependencies[name])
		targetVersions = appendBunTargetVersion(targetVersions, seen, workspace.OptionalDependencies[name])
		targetVersions = appendBunTargetVersion(targetVersions, seen, workspace.DevDependencies[name])
	}

	slices.Sort(targetVersions)

	return targetVersions
}

func appendBunTargetVersion(targetVersions []string, seen map[string]bool, version string) []string {
	if version == "" || seen[version] {
		return targetVersions
	}

	seen[version] = true

	return append(targetVersions, version)
}

func (e BunLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read bun.lock: %w", err)
	}

	var parsed BunLockfile
	if err := json.Unmarshal(jsonc.ToJSONInPlace(content), &parsed); err != nil {
		return nil, fmt.Errorf("could not parse bun.lock: %w", err)
	}

	packages := make([]lockfile.PackageDetails, 0, len(parsed.Packages))
	for _, tuple := range parsed.Packages {
		name, version, commit, err := structureBunPackageDetails(tuple)
		if err != nil || name == "" {
			continue
		}
		if strings.HasPrefix(version, "workspace:") {
			continue
		}

		packages = append(packages, lockfile.PackageDetails{
			Name:           name,
			Version:        version,
			Commit:         commit,
			TargetVersions: collectBunTargetVersions(parsed.Workspaces, name),
			Ecosystem:      models.EcosystemNPM,
			PackageManager: bunPackageManager,
		})
	}

	return packages, nil
}

var BunExtractor = BunLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageJSONMatcher{}}},
}

func ParseBunLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, BunExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.BunFilePath, BunExtractor)
}
