package codefile

import (
	"context"
	"os"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/converter"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// readFileContent is a thin wrapper over os.ReadFile that reads the content of a file
// and returns it as a byte slice.
// TODO(daniel.strong): find a better place for this function
func readFileContent(filePath string) ([]byte, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// parseFile parses fileContent with tsParser, canceling the parse as soon as ctx is done.
func parseFile(ctx context.Context, tsParser *treesitter.Parser, fileContent []byte) *treesitter.Tree {
	readCallback := func(offset int, position treesitter.Point) []byte {
		if ctx.Err() != nil {
			return []byte{}
		}
		if offset >= len(fileContent) {
			return []byte{}
		}

		return fileContent[offset:]
	}

	return tsParser.ParseWithOptions(readCallback, nil, &treesitter.ParseOptions{
		// ProgressCallback returns true to cancel parsing
		// We use ctx.Err() != nil to cancel the parse if the context is canceled
		// See: https://github.com/tree-sitter/go-tree-sitter/blob/adc13ffd8b2c0b01b878fda9f7c422ce0df5fad3/parser.go#L319
		ProgressCallback: func(_ treesitter.ParseState) bool {
			return ctx.Err() != nil
		},
	})
}

// buildPackageLocation converts a tree-sitter start/end position pair into a models.PackageLocation
// for a match found in the file at path (relative to dir).
func buildPackageLocation(dir string, path string, start treesitter.Point, end treesitter.Point) (models.PackageLocation, error) {
	packageLocation := models.PackageLocation{
		Filename: fileposition.ToRelativePath(dir, path),
	}

	var err error
	packageLocation.LineStart, err = converter.SafeUIntToInt(start.Row + 1)
	if err != nil {
		return models.PackageLocation{}, err
	}
	packageLocation.LineEnd, err = converter.SafeUIntToInt(end.Row + 1)
	if err != nil {
		return models.PackageLocation{}, err
	}
	packageLocation.ColumnStart, err = converter.SafeUIntToInt(start.Column + 1)
	if err != nil {
		return models.PackageLocation{}, err
	}
	packageLocation.ColumnEnd, err = converter.SafeUIntToInt(end.Column + 1)
	if err != nil {
		return models.PackageLocation{}, err
	}

	return packageLocation, nil
}

// recordMatch appends a reachable symbol match to detectionResults, initializing the
// per-purl and per-advisory maps if this is the first match for either.
func recordMatch(detectionResults models.DetectionResults, purl string, advisoryID string, symbol string, location models.PackageLocation) {
	if _, ok := detectionResults[purl]; !ok {
		detectionResults[purl] = make(map[string]models.ReachableSymbolLocations)
	}
	if _, ok := detectionResults[purl][advisoryID]; !ok {
		detectionResults[purl][advisoryID] = make(models.ReachableSymbolLocations, 0)
	}

	detectionResults[purl][advisoryID] = append(
		detectionResults[purl][advisoryID],
		models.ReachableSymbolLocation{
			Symbol:          symbol,
			PackageLocation: location,
		})
}
