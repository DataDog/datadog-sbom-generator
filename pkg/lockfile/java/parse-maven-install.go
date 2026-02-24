package java

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	var installFile MavenInstallFile
	if err := json.Unmarshal(contentBytes, &installFile); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to decode maven_install.json: %w", err)
	}
	if len(installFile.Artifacts) == 0 {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(contentBytes, &raw); err == nil {
			if _, hasDepTree := raw["dependency_tree"]; hasDepTree {
				log.Printf("maven_install.json uses unsupported v1 format (rules_jvm_external < 5.1), skipping: %s\n", f.Path())
				return []lockfile.PackageDetails{}, nil
			}
		}
	}

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

	for _, name := range artifactNames {
		artifact := installFile.Artifacts[name]
		artifact.FilePosition.Filename = f.Path()

		pkg := lockfile.PackageDetails{
			Name:           normalizeMavenInstallName(name),
			Version:        artifact.Version,
			PackageManager: mavenInstallPackageManager,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation:  artifact.FilePosition,
		}

		pkgKey := pkg.Name + "@" + pkg.Version
		if _, alreadySeen := seen[pkgKey]; alreadySeen {
			continue
		}
		seen[pkgKey] = struct{}{}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

func validateMavenInstallArtifacts(artifacts map[string]*MavenInstallArtifact) error {
	for name, artifact := range artifacts {
		if artifact == nil {
			return fmt.Errorf("invalid maven_install.json: artifact %q is null", name)
		}
	}

	return nil
}

func normalizeMavenInstallName(name string) string {
	parts := strings.SplitN(name, ":", 3)
	if len(parts) >= 2 {
		return parts[0] + ":" + parts[1]
	}

	return name
}

func ParseMavenInstall(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, MavenInstallExtractor{})
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.MavenInstallFilePath, MavenInstallExtractor{})
}
