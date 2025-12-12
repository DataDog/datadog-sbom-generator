package java

import (
	"encoding/xml"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e GradleVerificationMetadataExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) IsOfficiallySupported() bool {
	return gradleVerificationOfficiallySupported
}

func (e GradleVerificationMetadataExtractor) PackageManager() models.PackageManager {
	return gradleVerificationPackageManager
}

func (e GradleVerificationMetadataExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	err := xml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	pkgs := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		pkgs = append(pkgs, lockfile.PackageDetails{
			Name:           component.Group + ":" + component.Name,
			Version:        component.Version,
			PackageManager: gradleVerificationPackageManager,
			Ecosystem:      models.EcosystemMaven,
		})
	}

	return pkgs, nil
}

var GradleVerificationExtractor = GradleVerificationMetadataExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&BuildGradleMatcher{}}},
}

func ParseGradleVerificationMetadata(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, GradleVerificationExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.GradleVerificationFilePath, GradleVerificationExtractor)
}
