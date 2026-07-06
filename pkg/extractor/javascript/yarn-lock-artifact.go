package javascript

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// Compile-time check: YarnLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = YarnLockExtractor{}

// GetArtifact returns a ScannedArtifact for the adjacent package.json.
// If no adjacent package.json exists, it returns nil, nil.
func (e YarnLockExtractor) GetArtifact(f extractor.DepFile, _ extractor.ScanContext) (*models.ScannedArtifact, error) {
	return getArtifactFromAdjacentPackageJSON(f)
}
