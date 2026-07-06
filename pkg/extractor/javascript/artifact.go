package javascript

import (
	"encoding/json"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// packageJSONIdentity is the minimal subset of package.json needed by
// GetArtifact: the project name and workspace glob patterns.
type packageJSONIdentity struct {
	Name       string   `json:"name"`
	Workspaces []string `json:"workspaces"`
}

// getArtifactFromAdjacentPackageJSON is the shared implementation for all JS
// lockfile extractors' GetArtifact method. It opens the adjacent package.json,
// reads the name and workspaces fields, and returns a ScannedArtifact with
// workspace package.json files as ProjectDeps.
//
// Returns nil, nil when no adjacent package.json exists.
func getArtifactFromAdjacentPackageJSON(f extractor.DepFile) (*models.ScannedArtifact, error) {
	pkgFile, err := f.Open("package.json")
	if err != nil {
		return nil, nil // missing package.json is expected
	}
	defer pkgFile.Close()

	var pkg packageJSONIdentity
	if err := json.NewDecoder(pkgFile).Decode(&pkg); err != nil {
		return nil, nil // malformed package.json
	}

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      pkg.Name,
			Filename:  pkgFile.Path(),
			Ecosystem: models.EcosystemNPM,
		},
	}

	if len(pkg.Workspaces) > 0 {
		matches := globWorkspacePackageJsons(pkg.Workspaces, pkgFile.Path())
		baseDir := filepath.Dir(pkgFile.Path())
		for _, match := range matches {
			artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
				Filename: filepath.Join(baseDir, match),
			})
		}
	}

	return artifact, nil
}
