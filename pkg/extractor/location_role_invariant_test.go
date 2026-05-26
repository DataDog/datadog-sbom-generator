package extractor_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/parsers" // Register all extractors
)

// TestLocationRoleSetWhenBlockLocationIsValid verifies that every extractor sets
// LocationRole whenever it also sets a valid BlockLocation.
//
// This is an invariant that the reporter relies on: vulnerability_result.go uses
// LocationRole to populate the "role" field in the emitted PackageLocation. If an
// extractor populates BlockLocation but leaves LocationRole empty, the role will be
// blank in the SBOM output even though the location is meaningful.
//
// The test walks pkg/extractor/fixtures/, runs the registered extractor for each
// fixture file, and fails if any returned PackageDetails has a valid BlockLocation
// but an empty LocationRole.
func TestLocationRoleSetWhenBlockLocationIsValid(t *testing.T) {
	t.Parallel()

	fixturesRoot := "fixtures"
	context := testutil.GetTestContext()

	// Enable all registered parsers so FindExtractor can match fixture files.
	// An empty map disables every parser (FindExtractor checks enabledParsers[name] == true).
	allParsers := make(map[string]bool)
	for name := range extractor.ListSupportedExtractors() {
		allParsers[name] = true
	}

	err := filepath.WalkDir(fixturesRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		ext, _ := extractor.FindExtractor(path, allParsers)
		if ext == nil {
			return nil
		}

		f, err := extractor.OpenLocalDepFile(path)
		if err != nil {
			return nil // skip unreadable files
		}
		defer f.Close()

		packages, err := ext.Extract(f, context)
		if err != nil {
			return nil // skip files that fail to parse (invalid fixtures are intentional)
		}

		for _, pkg := range packages {
			if fileposition.IsFilePositionExtractedSuccessfully(pkg.BlockLocation) && pkg.LocationRole == "" {
				t.Errorf(
					"extractor for %q returned package %s@%s with a valid BlockLocation but empty LocationRole",
					path, pkg.Name, pkg.Version,
				)
			}
		}

		return nil
	})

	if err != nil {
		t.Fatalf("error walking fixtures: %v", err)
	}
}
