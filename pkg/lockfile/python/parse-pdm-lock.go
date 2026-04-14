package python

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

func (p PdmLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PdmFilePath.String()
}

func (p PdmLockExtractor) IsOfficiallySupported() bool {
	return pdmOfficiallySupported
}

func (p PdmLockExtractor) PackageManager() models.PackageManager {
	return pdmPackageManager
}

func (p PdmLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockFile *PdmLockFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	_, err = toml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockFile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	packages := make([]lockfile.PackageDetails, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		details := lockfile.PackageDetails{
			Name:           pkg.Name,
			Version:        pkg.Version,
			PackageManager: pdmPackageManager,
			Ecosystem:      models.EcosystemPyPI,
		}

		var optional = true
		for _, gr := range pkg.Groups {
			if gr == "dev" {
				details.DepGroups = append(details.DepGroups, "dev")
				optional = false
			} else if gr == "default" {
				optional = false
			}
		}
		if optional {
			details.DepGroups = append(details.DepGroups, "optional")
		}

		if pkg.Revision != "" {
			details.Commit = pkg.Revision
		}

		packages = append(packages, details)
	}

	// Set BlockLocation for each package using the InTOML utility
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	positions := make([]*models.FilePosition, len(packages))
	for i := range packages {
		positions[i] = &packages[i].BlockLocation
	}

	fileposition.InTOML("[[package]]", "", positions, lines)

	for i := range packages {
		packages[i].BlockLocation.Filename = f.Path()
	}

	return packages, nil
}

var _ lockfile.Extractor = PdmLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PdmFilePath, PdmLockExtractor{})
}

func ParsePdmLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PdmLockExtractor{})
}
