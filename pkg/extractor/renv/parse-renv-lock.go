package renv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	renvPackageManager      = models.Renv
	renvOfficiallySupported = false
)

type RenvPackage struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	Repository string `json:"Repository"`
}

type RenvLockfile struct {
	Packages map[string]RenvPackage `json:"Packages"`
}

type RenvLockExtractor struct{}

func (e RenvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.RenvFilePath.String()
}

func (e RenvLockExtractor) IsOfficiallySupported() bool {
	return renvOfficiallySupported
}

func (e RenvLockExtractor) PackageManager() models.PackageManager {
	return renvPackageManager
}

func (e RenvLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *RenvLockfile

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = json.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")

	// Build position map for InJSON keyed by package name
	positions := make(map[string]*models.FilePosition, len(parsedLockfile.Packages))
	for name := range parsedLockfile.Packages {
		positions[name] = &models.FilePosition{}
	}

	fileposition.InJSON("Packages", positions, lines, 0)

	packages := make([]extractor.PackageDetails, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		// currently we only support CRAN
		if pkg.Repository != string(models.EcosystemCRAN) {
			continue
		}

		pkgDetails := extractor.PackageDetails{
			Name:           pkg.Package,
			Version:        pkg.Version,
			PackageManager: renvPackageManager,
			Ecosystem:      models.EcosystemCRAN,
		}
		if pos, ok := positions[name]; ok {
			blockLocation := *pos
			blockLocation.Filename = f.Path()
			pkgDetails.BlockLocation = blockLocation
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var _ extractor.Extractor = RenvLockExtractor{}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.RenvFilePath, RenvLockExtractor{})
}

func ParseRenvLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, RenvLockExtractor{})
}
