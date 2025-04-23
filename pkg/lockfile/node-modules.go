package lockfile

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"path/filepath"
)

type NodeModulesExtractor struct{}

func (e NodeModulesExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "node_modules" && filepath.Base(path) == ".package-lock.json"
}

func (e NodeModulesExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	extractor := NpmLockExtractor{}

	return extractor.Extract(f)
}

var _ Extractor = NodeModulesExtractor{}
