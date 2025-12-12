package dart

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

const (
	pubsecPackageManager      = models.Pub
	pubsecFilePath            = models.PubFilePath
	pubsecOfficiallySupported = false
)

type PubspecLockDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
	Ref  string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &PubspecLockDescription{}

func (pld *PubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	var m struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
		Path string `yaml:"path"`
		Ref  string `yaml:"resolved-ref"`
	}

	err := value.Decode(&m)

	if err == nil {
		pld.Name = m.Name
		pld.Path = m.Path
		pld.URL = m.URL
		pld.Ref = m.Ref

		return nil
	}

	var str *string

	err = value.Decode(&str)

	if err != nil {
		return err
	}

	pld.Path = *str

	return nil
}

type PubspecLockPackage struct {
	Source      string                 `yaml:"source"`
	Description PubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
	Dependency  string                 `yaml:"dependency"`
}

type PubspecLockfile struct {
	Packages map[string]PubspecLockPackage `yaml:"packages,omitempty"`
	Sdks     map[string]string             `yaml:"sdks"`
}

type PubspecLockExtractor struct{}

func (e PubspecLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PubFilePath.String()
}

func (e PubspecLockExtractor) IsOfficiallySupported() bool {
	return pubsecOfficiallySupported
}

func (e PubspecLockExtractor) PackageManager() models.PackageManager {
	return pubsecPackageManager
}

func (e PubspecLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PubspecLockfile

	err := yaml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	if parsedLockfile == nil {
		return []lockfile.PackageDetails{}, nil
	}

	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		pkgDetails := lockfile.PackageDetails{
			Name:           name,
			Version:        pkg.Version,
			Commit:         pkg.Description.Ref,
			PackageManager: pubsecPackageManager,
			Ecosystem:      models.EcosystemPub,
		}
		for _, str := range strings.Split(pkg.Dependency, " ") {
			if str == "dev" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, "dev")
				break
			}
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var _ lockfile.Extractor = PubspecLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PubFilePath, PubspecLockExtractor{})
}

func ParsePubspecLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PubspecLockExtractor{})
}
