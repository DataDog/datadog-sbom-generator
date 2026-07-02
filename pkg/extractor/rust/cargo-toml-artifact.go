package rust

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// GetArtifact implements extractor.ArtifactExtractor.
// It opens the sibling Cargo.toml to extract the package name and discovers
// internal project dependencies via path-based dependency entries.
func (e CargoLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	cargoTomlFile, err := f.Open("Cargo.toml")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, nil
	}
	defer cargoTomlFile.Close()

	content, err := io.ReadAll(cargoTomlFile)
	if err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	var parsed CargoToml
	if err := toml.Unmarshal(content, &parsed); err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: f.Path()}}, err
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      parsed.Package.Name,
			Filename:  f.Path(),
			Ecosystem: models.EcosystemCratesIO,
		},
	}

	cargoTomlDir := filepath.Dir(cargoTomlFile.Path())
	seen := make(map[string]struct{})

	// Collect path dependencies from all three dependency sections.
	for _, deps := range []map[string]interface{}{parsed.Dependencies, parsed.DevDeps, parsed.BuildDeps} {
		collectPathDeps(deps, cargoTomlDir, ctx, seen, artifact)
	}

	return artifact, nil
}

// collectPathDeps scans a dependency section for entries with a `path` key and
// appends them as ProjectDeps on the artifact, deduplicating by resolved path.
func collectPathDeps(deps map[string]interface{}, cargoTomlDir string, ctx extractor.ScanContext, seen map[string]struct{}, artifact *models.ScannedArtifact) {
	if deps == nil {
		return
	}

	for _, depValue := range deps {
		depMap, ok := depValue.(map[string]interface{})
		if !ok {
			continue
		}

		pathStr, ok := depMap["path"].(string)
		if !ok || pathStr == "" {
			continue
		}

		targetDir := filepath.Join(cargoTomlDir, pathStr)
		targetCargoToml := filepath.Clean(filepath.Join(targetDir, "Cargo.toml"))

		if _, err := os.Stat(targetCargoToml); err != nil {
			continue
		}

		// Skip targets outside the scan root.
		if ctx.RootDir != "" {
			absRoot, err := filepath.Abs(ctx.RootDir)
			if err == nil {
				rel, err := filepath.Rel(absRoot, targetCargoToml)
				if err != nil || strings.HasPrefix(rel, "..") {
					continue
				}
			}
		}

		if _, ok := seen[targetCargoToml]; ok {
			continue
		}
		seen[targetCargoToml] = struct{}{}

		artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
			Filename: targetCargoToml,
		})
	}
}

var _ extractor.ArtifactExtractor = CargoLockExtractor{}
