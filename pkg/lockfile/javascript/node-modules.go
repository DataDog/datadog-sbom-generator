package javascript

import (
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e NodeModulesExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "node_modules" && filepath.Base(path) == ".package-lock.json"
}

func (e NodeModulesExtractor) IsOfficiallySupported() bool {
	return nodeModulesOfficiallySupported
}

func (e NodeModulesExtractor) PackageManager() models.PackageManager {
	return nodeModulesPackageManager
}

func (e NodeModulesExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	extractor := NpmLockExtractor{}

	return extractor.Extract(f, context)
}

var _ lockfile.Extractor = NodeModulesExtractor{}

var NodeModulesExtractorInstance = NodeModulesExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.NodeModulesPath, NodeModulesExtractorInstance)
}
