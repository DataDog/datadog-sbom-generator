package rust

import (
	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// Compile-time check: CargoLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = CargoLockExtractor{}

// GetArtifact returns a ScannedArtifact for the adjacent Cargo.toml.
// If no adjacent Cargo.toml exists, it returns nil, nil.
func (e CargoLockExtractor) GetArtifact(f extractor.DepFile, _ extractor.ScanContext) (*models.ScannedArtifact, error) {
	tomlFile, err := f.Open("Cargo.toml")
	if err != nil {
		return nil, nil // missing Cargo.toml is expected
	}
	defer tomlFile.Close()

	artifact := &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Filename:  tomlFile.Path(),
			Ecosystem: models.EcosystemCratesIO,
		},
	}

	var manifest struct {
		Package *struct {
			Name string `toml:"name"`
		} `toml:"package"`
	}
	if _, err := toml.NewDecoder(tomlFile).Decode(&manifest); err == nil && manifest.Package != nil {
		artifact.PackageName = manifest.Package.Name
	}

	return artifact, nil
}
