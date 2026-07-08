package javascript

import (
	"encoding/json"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// workspaceGlobs handles both array-form and object-form package.json workspaces:
//   - Array form:  "workspaces": ["packages/*"]
//   - Object form: "workspaces": {"packages": ["packages/*"], "nohoist": [...]}
type workspaceGlobs []string

func (w *workspaceGlobs) UnmarshalJSON(data []byte) error {
	// Try array form first (most common).
	var globs []string
	if err := json.Unmarshal(data, &globs); err == nil {
		*w = globs

		return nil
	}

	// Fall back to object form: extract the "packages" key.
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*w = obj.Packages

	return nil
}

// packageJSONIdentity is the minimal subset of package.json needed by
// GetArtifact: the project name and workspace glob patterns.
type packageJSONIdentity struct {
	Name       string         `json:"name"`
	Workspaces workspaceGlobs `json:"workspaces"`
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
			childPath := filepath.Join(baseDir, match)
			artifact.ProjectDeps = append(artifact.ProjectDeps, models.ArtifactDetail{
				Name:      readPackageJSONName(childPath),
				Filename:  childPath,
				Ecosystem: models.EcosystemNPM,
			})
		}
	}

	return artifact, nil
}

// readPackageJSONName reads the `name` field from a package.json file.
// Returns empty string if the file cannot be read or has no name.
func readPackageJSONName(pkgJSONPath string) string {
	f, err := extractor.OpenLocalDepFile(pkgJSONPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	var pkg struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(f).Decode(&pkg); err != nil {
		return ""
	}

	return pkg.Name
}
