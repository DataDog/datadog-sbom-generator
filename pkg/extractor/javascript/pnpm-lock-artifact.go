package javascript

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"gopkg.in/yaml.v3"
)

// Compile-time check: PnpmLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = PnpmLockExtractor{}

// GetArtifact returns a ScannedArtifact for the adjacent package.json.
// Workspace package.json paths are sourced from the pnpm-lock.yaml importers
// map, so pnpm-workspace.yaml-only workspaces are also covered.
// Returns nil, nil when no adjacent package.json exists.
func (e PnpmLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	pkgFile, err := f.Open("package.json")
	if err != nil {
		return nil, nil
	}
	defer pkgFile.Close()

	var pkg packageJSONIdentity
	if err := json.NewDecoder(pkgFile).Decode(&pkg); err != nil {
		return nil, nil
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      pkg.Name,
			Filename:  pkgFile.Path(),
			Ecosystem: models.EcosystemNPM,
		},
	}

	// Parse the lockfile to discover workspace packages via importers.
	content, err := io.ReadAll(f)
	if err != nil {
		return artifact, nil
	}

	var lockfile PnpmLockfile
	if err := yaml.NewDecoder(bytes.NewReader(content)).Decode(&lockfile); err != nil {
		return artifact, nil
	}

	lockfileDir := filepath.Dir(f.Path())
	seen := make(map[string]struct{})

	for workspacePath := range lockfile.Importers {
		if workspacePath == "." {
			continue // root package — already the artifact itself
		}

		targetPkgJSON := filepath.Clean(filepath.Join(lockfileDir, workspacePath, "package.json"))
		if _, err := os.Stat(targetPkgJSON); err != nil {
			continue
		}

		// Skip targets that escape the scan root (e.g. "../shared/package.json").
		if ctx.RootDir != "" {
			absRoot, err := filepath.Abs(ctx.RootDir)
			if err == nil {
				rel, relErr := filepath.Rel(absRoot, targetPkgJSON)
				if relErr != nil || strings.HasPrefix(rel, "..") {
					continue
				}
			}
		}

		if _, ok := seen[targetPkgJSON]; ok {
			continue
		}

		seen[targetPkgJSON] = struct{}{}
		artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
			Name:      readPackageJSONName(targetPkgJSON),
			Filename:  targetPkgJSON,
			Ecosystem: models.EcosystemNPM,
		})
	}

	return artifact, nil
}
