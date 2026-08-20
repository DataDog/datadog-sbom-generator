package codefile

import (
	"context"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// Detector parses source files for one language and matches vulnerable symbols against how
// those symbols are actually imported and called in that source.
type Detector interface {
	Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error
	Close()
}

var (
	_ Detector = (*ReachabilityJava)(nil)
	_ Detector = (*ReachabilityGo)(nil)
)
