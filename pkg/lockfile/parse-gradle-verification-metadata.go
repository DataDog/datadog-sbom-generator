package lockfile

import (
	"encoding/xml"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

type GradleVerificationMetadataFile struct {
	Components []struct {
		Group   string `xml:"group,attr"`
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
	} `xml:"components>component"`
}

type GradleVerificationMetadataExtractor struct {
	WithMatcher
}

func (e GradleVerificationMetadataExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) Extract(f DepFile) ([]models.PackageDetails, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	err := xml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []models.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	pkgs := make([]models.PackageDetails, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		pkgs = append(pkgs, models.PackageDetails{
			Name:           component.Group + ":" + component.Name,
			Version:        component.Version,
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		})
	}

	return pkgs, nil
}

var GradleVerificationExtractor = GradleVerificationMetadataExtractor{
	WithMatcher{Matchers: []Matcher{&BuildGradleMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("gradle/verification-metadata.xml", GradleVerificationMetadataExtractor{})
}

func ParseGradleVerificationMetadata(pathToLockfile string) ([]models.PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, GradleVerificationExtractor)
}
