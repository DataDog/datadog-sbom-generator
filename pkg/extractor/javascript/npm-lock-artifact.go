package javascript

import (
	"encoding/json"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// Compile-time check: NpmLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = NpmLockExtractor{}

// packageJSONIdentity is the minimal subset of package.json needed by
// GetArtifact: the project name and workspace glob patterns.
type packageJSONIdentity struct {
	Name       string   `json:"name"`
	Workspaces []string `json:"workspaces"`
}

// GetArtifact returns a ScannedArtifact for the adjacent package.json.
// If no adjacent package.json exists, it returns nil, nil.
func (e NpmLockExtractor) GetArtifact(f extractor.DepFile, _ extractor.ScanContext) (*models.ScannedArtifact, error) {
	pkgFile, err := f.Open("package.json")
	if err != nil {
		return nil, nil //nolint:nilerr // missing package.json is expected
	}
	defer pkgFile.Close()

	var pkg packageJSONIdentity
	if err := json.NewDecoder(pkgFile).Decode(&pkg); err != nil {
		return nil, nil //nolint:nilerr // malformed package.json
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
