package scanner

import (
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/pathexclusion"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	extractorpython "github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	extractorsystem "github.com/DataDog/datadog-sbom-generator/pkg/extractor/system"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// packageExclusionSeparator separates the ecosystem from the package name in a
// sca.ignore-packages entry, e.g. "npm:lodash".
const packageExclusionSeparator = ":"

type exclusionMatch struct {
	pattern string
	source  exclusionSource
}

type exclusionSource string

const (
	exclusionSourceCLI    exclusionSource = "cli"
	exclusionSourceConfig exclusionSource = "config"
)

// matchExclusion checks both exclusion sources for a scanned file.
func matchExclusion(r reporter.Reporter, scanRoot string, repoRoot string, path string, cliExcludePaths []string, configExcludePaths []string) (*exclusionMatch, error) {
	if len(cliExcludePaths) == 0 && len(configExcludePaths) == 0 {
		return nil, nil
	}

	if len(cliExcludePaths) > 0 {
		shouldExcludePath, pattern, err := matchCLIExclusion(scanRoot, path, cliExcludePaths)
		if err != nil {
			return nil, err
		}
		if shouldExcludePath {
			return &exclusionMatch{pattern: pattern, source: exclusionSourceCLI}, nil
		}
	}

	if len(configExcludePaths) > 0 {
		if shouldExcludePath, pattern := matchConfigExclusion(repoRoot, path, configExcludePaths, r); shouldExcludePath {
			return &exclusionMatch{pattern: pattern, source: exclusionSourceConfig}, nil
		}
	}

	return nil, nil
}

// matchCLIExclusion applies CLI --exclude patterns relative to the current scan root.
func matchCLIExclusion(scanRoot string, path string, cliExcludePaths []string) (bool, string, error) {
	return fileposition.ShouldExcludePath(scanRoot, path, cliExcludePaths)
}

// matchConfigExclusion applies unified configuration exclusions relative to the
// repository root.
func matchConfigExclusion(repoRoot string, path string, configExcludePaths []string, r reporter.Reporter) (bool, string) {
	matched, pattern, errs := pathexclusion.MatchConfigExcludePath(repoRoot, path, configExcludePaths)
	for _, err := range errs {
		r.Warnf("[config] Failed to evaluate exclusion pattern: %v\n", err)
	}

	return matched, pattern
}

// ecosystemForExtractor returns the models.Ecosystem an extractor's packages always belong to,
// and whether that ecosystem is known before parsing the matched file. Extractors whose ecosystem
// depends on file contents (e.g. CSV, OSV scan results) return ok=false since it cannot be
// determined upfront, and are therefore never skipped by ignore-ecosystems.
func ecosystemForExtractor(ext extractor.Extractor) (models.Ecosystem, bool) {
	switch ext.(type) {
	case extractorsystem.DpkgStatusExtractor:
		return models.EcosystemDebian, true
	case extractorsystem.ApkInstalledExtractor:
		return models.EcosystemAlpine, true
	case extractorpython.PyProjectTOMLExtractor:
		return models.EcosystemPyPI, true
	case extractor.CSVExtractor, extractor.OSVScannerResultsExtractor:
		return "", false
	}

	eco, ok := models.PackageManagerToEcosystem[ext.PackageManager()]

	return eco, ok
}

// matchEcosystemExclusion checks a matched extractor's ecosystem against the unified
// configuration's ignore-ecosystems set. It mirrors matchConfigExclusion but keyed by
// ecosystem instead of path, letting the scan skip parsing the file entirely on a match.
func matchEcosystemExclusion(ext extractor.Extractor, configExcludeEcosystems []string) (bool, models.Ecosystem) {
	if len(configExcludeEcosystems) == 0 {
		return false, ""
	}

	eco, ok := ecosystemForExtractor(ext)
	if !ok {
		return false, ""
	}

	for _, excluded := range configExcludeEcosystems {
		if excluded == string(eco) {
			return true, eco
		}
	}

	return false, ""
}

// matchPackageExclusion checks a scanned package's "<ecosystem>:<name>" identity against the
// unified configuration's ignore-packages set. Matching ignores the package version, so an
// entry excludes the package at any version.
func matchPackageExclusion(pkg extractor.PackageDetails, configExcludePackages []string) bool {
	if len(configExcludePackages) == 0 {
		return false
	}

	key := string(pkg.Ecosystem) + packageExclusionSeparator + pkg.Name

	for _, excluded := range configExcludePackages {
		if excluded == key {
			return true
		}
	}

	return false
}
