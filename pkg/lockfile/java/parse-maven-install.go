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
	// Accept "maven_install.json" and any "{name}_maven_install.json" variant.
	// rules_jvm_external recommends naming custom lock files after their
	// maven_install repository name (e.g. "foo_maven_install.json").
	return strings.HasSuffix(filepath.Base(path), models.MavenInstallFilePath.String())
}

func (e MavenInstallExtractor) IsOfficiallySupported() bool {
	return mavenInstallOfficiallySupported
}

func (e MavenInstallExtractor) PackageManager() models.PackageManager {
	return mavenInstallPackageManager
}

// IsDirect is not set. For v1/v2 lockfiles, determining which artifacts are direct requires
// cross-referencing WORKSPACE/MODULE.bazel declarations. For v3, direct deps could be derived
// from the per-artifact __INPUT_ARTIFACTS_HASH dict (its non-"repositories" keys), but this
// is left as a future improvement.
func (e MavenInstallExtractor) Extract(f lockfile.DepFile, _ lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	var installFile mavenInstallLockfile
	if err := json.Unmarshal(contentBytes, &installFile); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not decode %s: %w", f.Path(), err)
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
		// Normalise to group:artifact@version. The artifacts map can contain
		// multiple keys for the same component (e.g. "g:a" and "g:a:pom"), but
		// all packaging/extension variants share the same version field and
		// collapse to the same pkg:maven PURL, so emitting them once is intentional.
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
//
// Two formats are supported:
//
//   - Maven form (no "@" suffix): "group:artifact", "group:artifact:version",
//     "group:artifact:packaging:version", or "group:artifact:packaging:classifier:version".
//     The version is the last colon-separated segment.
//
//   - Gradle external form (has "@ext" suffix): "group:artifact:version@ext" or
//     "group:artifact:version:classifier@ext".
//     The "@ext" suffix is stripped and the version is the first segment after group:artifact.
func parseMavenCoord(coord string) (name string, version string) {
	gradleExternalForm := strings.Contains(coord, "@")
	if gradleExternalForm {
		if idx := strings.Index(coord, "@"); idx >= 0 {
			coord = coord[:idx]
		}
	}

	parts := strings.SplitN(coord, ":", 3)
	if len(parts) < 2 {
		return coord, ""
	}
	name = parts[0] + ":" + parts[1]
	if len(parts) == 2 {
		return name, ""
	}
	rest := parts[2]

	if gradleExternalForm {
		// g:a:version or g:a:version:classifier — version is the first segment.
		if idx := strings.Index(rest, ":"); idx >= 0 {
			return name, rest[:idx]
		}

		return name, rest
	}

	// Maven form: g:a[:packaging[:classifier]]:version — version is the last segment.
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
