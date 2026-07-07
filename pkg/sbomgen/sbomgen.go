// Package sbomgen provides a library API for generating CycloneDX SBOMs.
//
// This package wraps the scanner and output internals to provide a simple,
// programmatic interface for SBOM generation without requiring CLI dependencies.
//
// Usage:
//
//	result, err := sbomgen.GenerateSBOM([]string{"./my-project"}, sbomgen.DefaultOptions())
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Println(string(result))
package sbomgen

import (
	"bytes"
	"errors"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/DataDog/datadog-sbom-generator/internal/output"
	"github.com/DataDog/datadog-sbom-generator/internal/output/sbom"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/DataDog/datadog-sbom-generator/pkg/scanner"
)

// Options controls the behavior of GenerateSBOM.
type Options struct {
	// Recursive controls whether subdirectories are scanned.
	Recursive bool

	// ExcludePaths is a list of glob patterns to exclude from scanning.
	ExcludePaths []string

	// ManifestParsers enables extractors that read manifest files (e.g.
	// pyproject.toml, package.json) as package sources when no lockfile is
	// present. Additive to the default lockfile extractor set.
	ManifestParsers bool

	// ExtractArtifactIds controls whether build file artifact IDs and dependency
	// relationships are extracted and included in the SBOM. When true, extractors
	// that implement ArtifactExtractor produce file-type components and dependency
	// edges, enabling GetBuildFileTrees dependency and ID resolution.
	// Enabling this also activates manifest parsers internally, because manifest
	// extractors (e.g. PyProjectTOMLExtractor) are needed to call GetArtifact.
	// Defaults to true in DefaultOptions.
	ExtractArtifactIds bool
}

// DefaultOptions returns Options with sensible defaults:
// recursive scanning enabled, no exclusions, and artifact extraction enabled.
func DefaultOptions() Options {
	return Options{
		Recursive:          true,
		ExcludePaths:       []string{},
		ExtractArtifactIds: true,
	}
}

// GenerateSBOM scans the given directories for lockfiles and returns a
// CycloneDX 1.5 SBOM as pretty-printed JSON bytes.
//
// It returns an error if dirs is empty or if the scan finds no packages.
func GenerateSBOM(dirs []string, opts Options) ([]byte, error) {
	if len(dirs) == 0 {
		return nil, errors.New("at least one directory must be provided")
	}

	actions := scanner.ScannerActions{
		DirectoryPaths:     dirs,
		ExcludePaths:       opts.ExcludePaths,
		Recursive:          opts.Recursive,
		ManifestParsers:    opts.ManifestParsers || opts.ExtractArtifactIds,
		ExtractArtifactIds: opts.ExtractArtifactIds,
	}

	r := reporter.NewCycloneDXReporter(&bytes.Buffer{}, &bytes.Buffer{}, reporter.WarnLevel)

	vulnResults, err := scanner.DoScan(actions, r)
	if err != nil {
		return nil, err
	}

	tool := sbom.Tool{
		Name:    "datadog-sbom-generator",
		Version: "library",
	}

	bom, bomErr := output.CreateCycloneDXBOM(tool, &vulnResults)
	if bom == nil {
		return nil, bomErr
	}

	if opts.ExtractArtifactIds {
		AddNpmWorkspaceEdges(bom, dirs[0])
	}

	var buf bytes.Buffer
	encoder := cyclonedx.NewBOMEncoder(&buf, cyclonedx.BOMFileFormatJSON)
	encoder.SetPretty(true)

	if encErr := encoder.EncodeVersion(bom, bom.SpecVersion); encErr != nil {
		return nil, errors.Join(encErr, bomErr)
	}

	return buf.Bytes(), bomErr
}
