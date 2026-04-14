package python

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"maps"
)

func (e PipenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PipfileFilePath.String()
}

func (e PipenvLockExtractor) IsOfficiallySupported() bool {
	return pipenvOfficiallySupported
}

func (e PipenvLockExtractor) PackageManager() models.PackageManager {
	return pipenvPackageManager
}

func (e PipenvLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PipenvLock

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = json.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	// Build position maps for InJSON
	defaultPositions := make(map[string]*models.FilePosition, len(parsedLockfile.Packages))
	for name := range parsedLockfile.Packages {
		defaultPositions[name] = &models.FilePosition{}
	}

	developPositions := make(map[string]*models.FilePosition, len(parsedLockfile.PackagesDev))
	for name := range parsedLockfile.PackagesDev {
		developPositions[name] = &models.FilePosition{}
	}

	fileposition.InJSON("default", defaultPositions, lines, 0)
	fileposition.InJSON("develop", developPositions, lines, 0)

	details := make(map[string]lockfile.PackageDetails)

	addPkgDetails(details, parsedLockfile.Packages, "", defaultPositions, f.Path())
	addPkgDetails(details, parsedLockfile.PackagesDev, "dev", developPositions, f.Path())

	return slices.Collect(maps.Values(details)), nil
}

func addPkgDetails(
	details map[string]lockfile.PackageDetails,
	packages map[string]PipenvPackage,
	group string,
	positions map[string]*models.FilePosition,
	filePath string,
) {
	for name, pipenvPackage := range packages {
		if pipenvPackage.Version == "" {
			continue
		}

		version := pipenvPackage.Version[2:]

		if _, ok := details[name+"@"+version]; !ok {
			pkgDetails := lockfile.PackageDetails{
				Name:           name,
				Version:        version,
				PackageManager: pipenvPackageManager,
				Ecosystem:      models.EcosystemPyPI,
				LocationRole:   models.LocationRoleLockfile,
			}
			if group != "" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, group)
			}
			if pos, ok := positions[name]; ok {
				blockLocation := *pos
				blockLocation.Filename = filePath
				pkgDetails.BlockLocation = blockLocation
			}
			details[name+"@"+version] = pkgDetails
		}
	}
}

var PipenvExtractor = PipenvLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PipfileMatcher{}}},
}

func ParsePipenvLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PipenvExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PipfileFilePath, PipenvExtractor)
}
