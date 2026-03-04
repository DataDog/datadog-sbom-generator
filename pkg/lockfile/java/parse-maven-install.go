package java

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e MavenInstallExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.MavenInstallFilePath.String()
}

func (e MavenInstallExtractor) IsOfficiallySupported() bool {
	return mavenInstallOfficiallySupported
}

func (e MavenInstallExtractor) PackageManager() models.PackageManager {
	return mavenInstallPackageManager
}

// IsDirect is not set: it would require parsing maven_install.bzl (Starlark) to resolve which artifacts are direct.
func (e MavenInstallExtractor) Extract(f lockfile.DepFile, _ lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to read maven_install.json: %w", err)
	}

	var installFile mavenInstallLockfile
	if err := json.Unmarshal(contentBytes, &installFile); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to decode maven_install.json: %w", err)
	}

	if len(installFile.Artifacts) == 0 {
		var depTreeFile mavenInstallDepTreeLockfile
		if err := json.Unmarshal(contentBytes, &depTreeFile); err == nil && len(depTreeFile.DependencyTree.Dependencies) > 0 {
			return extractMavenInstallDepTree(depTreeFile)
		}

		return []lockfile.PackageDetails{}, nil
	}

	return extractMavenInstallArtifacts(installFile, contentBytes, f.Path())
}

func extractMavenInstallArtifacts(installFile mavenInstallLockfile, contentBytes []byte, filePath string) ([]lockfile.PackageDetails, error) {
	if err := validateMavenInstallArtifacts(installFile.Artifacts); err != nil {
		return []lockfile.PackageDetails{}, err
	}

	lines := strings.Split(string(contentBytes), "\n")
	fileposition.InJSON("artifacts", installFile.Artifacts, lines, 0)

	artifactNames := make([]string, 0, len(installFile.Artifacts))
	for name := range installFile.Artifacts {
		artifactNames = append(artifactNames, name)
	}
	sort.Strings(artifactNames)

	pkgs := make([]lockfile.PackageDetails, 0, len(installFile.Artifacts))
	seen := make(map[string]struct{}, len(installFile.Artifacts))

	for _, rawName := range artifactNames {
		artifact := installFile.Artifacts[rawName]
		artifact.FilePosition.Filename = filePath

		name, _ := parseMavenCoord(rawName)
		pkgKey := name + "@" + artifact.Version
		if _, exists := seen[pkgKey]; exists {
			continue
		}
		seen[pkgKey] = struct{}{}

		pkgs = append(pkgs, lockfile.PackageDetails{
			Name:           name,
			Version:        artifact.Version,
			PackageManager: mavenInstallPackageManager,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation:  artifact.FilePosition,
		})
	}

	return pkgs, nil
}

func extractMavenInstallDepTree(depTreeFile mavenInstallDepTreeLockfile) ([]lockfile.PackageDetails, error) {
	deps := depTreeFile.DependencyTree.Dependencies

	sort.Slice(deps, func(i, j int) bool {
		return deps[i].Coord < deps[j].Coord
	})

	pkgs := make([]lockfile.PackageDetails, 0, len(deps))
	seen := make(map[string]struct{}, len(deps))

	for _, dep := range deps {
		name, version := parseMavenCoord(dep.Coord)

		pkgKey := name + "@" + version
		if _, exists := seen[pkgKey]; exists {
			continue
		}
		seen[pkgKey] = struct{}{}

		pkgs = append(pkgs, lockfile.PackageDetails{
			Name:           name,
			Version:        version,
			PackageManager: mavenInstallPackageManager,
			Ecosystem:      models.EcosystemMaven,
		})
	}

	return pkgs, nil
}

func validateMavenInstallArtifacts(artifacts map[string]*mavenInstallArtifact) error {
	for name, artifact := range artifacts {
		if artifact == nil {
			return fmt.Errorf("invalid maven_install.json: artifact %q is null", name)
		}
	}

	return nil
}

// parseMavenCoord extracts the group:artifact name and version from a Maven coordinate.
// Coordinates can be "group:artifact", "group:artifact:version",
// "group:artifact:packaging:version", or "group:artifact:packaging:classifier:version".
// The name is always "group:artifact". The version is the last segment when 3+ parts exist.
func parseMavenCoord(coord string) (name string, version string) {
	parts := strings.SplitN(coord, ":", 3)
	if len(parts) < 2 {
		return coord, ""
	}
	name = parts[0] + ":" + parts[1]
	if len(parts) == 2 {
		return name, ""
	}
	// parts[2] may be "version", "packaging:version", or "packaging:classifier:version".
	// In all cases the version is the last colon-separated segment.
	rest := parts[2]
	if idx := strings.LastIndex(rest, ":"); idx >= 0 {
		return name, rest[idx+1:]
	}

	return name, rest
}

func ParseMavenInstall(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, MavenInstallExtractor{})
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.MavenInstallFilePath, MavenInstallExtractor{})
}
