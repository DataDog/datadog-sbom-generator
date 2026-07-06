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
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: cargoTomlFile.Path()}}, err
	}

	var parsed CargoToml
	if err := toml.Unmarshal(content, &parsed); err != nil {
		return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: cargoTomlFile.Path()}}, err
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      parsed.Package.Name,
			Filename:  cargoTomlFile.Path(),
			Ecosystem: models.EcosystemCratesIO,
		},
	}

	cargoTomlDir := filepath.Dir(cargoTomlFile.Path())
	seen := make(map[string]struct{})

	// Collect path dependencies from all three dependency sections.
	for _, deps := range []map[string]interface{}{parsed.Dependencies, parsed.DevDeps, parsed.BuildDeps} {
		collectPathDeps(deps, cargoTomlDir, ctx, seen, artifact)
	}

	// Collect workspace member satellites if this is a workspace manifest.
	if len(parsed.Workspace.Members) > 0 {
		artifact.Satellites = collectWorkspaceMembers(parsed.Workspace.Members, cargoTomlDir, ctx)
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

// collectWorkspaceMembers expands workspace member patterns (literal paths
// and single-star globs) and creates a satellite ScannedArtifact for each
// member crate that contains a Cargo.toml.
func collectWorkspaceMembers(members []string, workspaceDir string, ctx extractor.ScanContext) []*models.ScannedArtifact {
	seen := make(map[string]struct{})
	var satellites []*models.ScannedArtifact

	for _, pattern := range members {
		fullPattern := filepath.Join(workspaceDir, pattern)
		matches, err := filepath.Glob(fullPattern)
		if err != nil || len(matches) == 0 {
			// For literal paths that are not globs, try using the pattern directly.
			matches = []string{fullPattern}
		}

		for _, match := range matches {
			memberToml := filepath.Clean(filepath.Join(match, "Cargo.toml"))
			if _, err := os.Stat(memberToml); err != nil {
				continue
			}

			absToml, err := filepath.Abs(memberToml)
			if err != nil {
				continue
			}
			if _, ok := seen[absToml]; ok {
				continue
			}
			seen[absToml] = struct{}{}

			// Skip members outside the scan root.
			if ctx.RootDir != "" {
				absRoot, err := filepath.Abs(ctx.RootDir)
				if err == nil {
					rel, err := filepath.Rel(absRoot, absToml)
					if err != nil || strings.HasPrefix(rel, "..") {
						continue
					}
				}
			}

			data, err := os.ReadFile(memberToml)
			if err != nil {
				continue
			}

			var memberParsed CargoToml
			if err := toml.Unmarshal(data, &memberParsed); err != nil {
				continue
			}

			sat := &models.ScannedArtifact{
				ArtifactDetail: models.ArtifactDetail{
					Name:      memberParsed.Package.Name,
					Filename:  memberToml,
					Ecosystem: models.EcosystemCratesIO,
				},
			}

			// Collect path deps for this member crate.
			memberDir := filepath.Dir(memberToml)
			memberSeen := make(map[string]struct{})
			for _, deps := range []map[string]interface{}{memberParsed.Dependencies, memberParsed.DevDeps, memberParsed.BuildDeps} {
				collectPathDeps(deps, memberDir, ctx, memberSeen, sat)
			}

			satellites = append(satellites, sat)
		}
	}

	return satellites
}

var _ extractor.ArtifactExtractor = CargoLockExtractor{}
