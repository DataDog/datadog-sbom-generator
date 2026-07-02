package codefile

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/converter"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

// symbolTypeFunction is the only Go symbol type currently understood.
const symbolTypeFunction = "function"

const tsQueryForGoImports = `
(import_spec
	name: (package_identifier)? @alias
	path: (interpreted_string_literal (interpreted_string_literal_content) @path))
`

const tsQueryForGoCall = `
(call_expression
	function: (selector_expression
		operand: (identifier) @pkg
		field: (field_identifier) @fn) @selector)
`

var majorVersionSuffixPattern = cachedregexp.MustCompile(`^v[0-9]+$`)

type ReachabilityGo struct {
	tsParser    *treesitter.Parser
	importQuery *treesitter.Query
	callQuery   *treesitter.Query

	aliasCaptureIdx    uint
	pathCaptureIdx     uint
	pkgCaptureIdx      uint
	fnCaptureIdx       uint
	selectorCaptureIdx uint

	reporter reporter.Reporter
}

// NewGoReachableDetector creates a new ReachabilityGo instance that once instantiated can be
// used to parse Go files. You should call Close() on the instance once you're finished parsing.
func NewGoReachableDetector(r reporter.Reporter) (*ReachabilityGo, error) {
	tsLanguage := treesitter.NewLanguage(tree_sitter_go.Language())

	tsParser := treesitter.NewParser()
	if err := tsParser.SetLanguage(tsLanguage); err != nil {
		return nil, fmt.Errorf("failed to set tree-sitter Go language on parser: %w", err)
	}

	importQuery, err := treesitter.NewQuery(tsLanguage, tsQueryForGoImports)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for Go imports: %w", err)
	}

	callQuery, err := treesitter.NewQuery(tsLanguage, tsQueryForGoCall)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for Go calls: %w", err)
	}

	aliasCaptureIdx, _ := importQuery.CaptureIndexForName("alias")
	pathCaptureIdx, _ := importQuery.CaptureIndexForName("path")
	pkgCaptureIdx, _ := callQuery.CaptureIndexForName("pkg")
	fnCaptureIdx, _ := callQuery.CaptureIndexForName("fn")
	selectorCaptureIdx, _ := callQuery.CaptureIndexForName("selector")

	return &ReachabilityGo{
		tsParser:           tsParser,
		importQuery:        importQuery,
		callQuery:          callQuery,
		aliasCaptureIdx:    aliasCaptureIdx,
		pathCaptureIdx:     pathCaptureIdx,
		pkgCaptureIdx:      pkgCaptureIdx,
		fnCaptureIdx:       fnCaptureIdx,
		selectorCaptureIdx: selectorCaptureIdx,
		reporter:           reporter.Effective(r),
	}, nil
}

// Close closes all hanging tree-sitter related resources.
// This should only be called once you're finished parsing all Go files.
func (r *ReachabilityGo) Close() {
	r.tsParser.Close()
	r.importQuery.Close()
	r.callQuery.Close()
}

// resolveImportAliases walks all import specs in the parsed tree and returns a map of module
// import path -> local identifiers used to reference that module in this file. Unaliased
// imports are assigned a heuristic identifier: the last path segment, with a trailing
// major-version suffix (e.g. "/v2") stripped, per Go module convention. Dot imports and blank
// imports are intentionally not resolved to any identifier.
func (r *ReachabilityGo) resolveImportAliases(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) map[string][]string {
	moduleToAliases := make(map[string][]string)

	matches := queryCursor.Matches(r.importQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var alias, modulePath string

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(r.aliasCaptureIdx):
				alias = capture.Node.Utf8Text(fileContent)
			case uint32(r.pathCaptureIdx):
				modulePath = capture.Node.Utf8Text(fileContent)
			}
		}

		if modulePath == "" {
			continue
		}

		if alias == "" {
			alias = defaultIdentifierForModulePath(modulePath)
		}

		moduleToAliases[modulePath] = append(moduleToAliases[modulePath], alias)
	}

	return moduleToAliases
}

// defaultIdentifierForModulePath derives the package identifier Go code would use for an
// unaliased import, using the last path segment and stripping a trailing major-version suffix
// (e.g. "github.com/foo/bar/v2" -> "bar").
func defaultIdentifierForModulePath(modulePath string) string {
	segments := strings.Split(modulePath, "/")
	identifier := segments[len(segments)-1]

	if len(segments) > 1 && majorVersionSuffixPattern.MatchString(identifier) {
		identifier = segments[len(segments)-2]
	}

	return identifier
}

func (r *ReachabilityGo) Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error {
	fileContent, err := readFileContent(path)
	if err != nil {
		return err
	}

	readCallback := func(offset int, position treesitter.Point) []byte {
		if ctx.Err() != nil {
			return []byte{}
		}
		if offset >= len(fileContent) {
			return []byte{}
		}

		return fileContent[offset:]
	}

	tree := r.tsParser.ParseWithOptions(readCallback, nil, &treesitter.ParseOptions{
		ProgressCallback: func(_ treesitter.ParseState) bool {
			return ctx.Err() != nil
		},
	})
	defer tree.Close()

	if len(advisoriesToCheck) == 0 {
		return nil
	}

	importCursor := treesitter.NewQueryCursor()
	defer importCursor.Close()
	moduleToAliases := r.resolveImportAliases(tree, fileContent, importCursor)

	callCursor := treesitter.NewQueryCursor()
	defer callCursor.Close()

	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			if s.Type != symbolTypeFunction {
				r.reporter.Warnf("No Go detection support for symbol type %s", s.Type)
				continue
			}

			aliases, moduleImported := moduleToAliases[s.Value]
			if !moduleImported {
				continue
			}

			matches := callCursor.Matches(r.callQuery, tree.RootNode(), fileContent)
			for match := matches.Next(); match != nil; match = matches.Next() {
				var pkgText, fnText string
				var selectorNode treesitter.Node

				for _, capture := range match.Captures {
					switch capture.Index {
					case uint32(r.pkgCaptureIdx):
						pkgText = capture.Node.Utf8Text(fileContent)
					case uint32(r.fnCaptureIdx):
						fnText = capture.Node.Utf8Text(fileContent)
					case uint32(r.selectorCaptureIdx):
						selectorNode = capture.Node
					}
				}

				if fnText != s.Name || !slices.Contains(aliases, pkgText) {
					continue
				}

				startPosition := selectorNode.StartPosition()
				endPosition := selectorNode.EndPosition()

				if _, ok := detectionResults[advisoryToCheck.Purl]; !ok {
					detectionResults[advisoryToCheck.Purl] = make(map[string]models.ReachableSymbolLocations)
				}
				if _, ok := detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID]; !ok {
					detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID] = make(models.ReachableSymbolLocations, 0)
				}

				packageLocation := models.PackageLocation{
					Filename: fileposition.ToRelativePath(dir, path),
				}
				packageLocation.LineStart, err = converter.SafeUIntToInt(startPosition.Row + 1)
				if err != nil {
					return err
				}
				packageLocation.LineEnd, err = converter.SafeUIntToInt(endPosition.Row + 1)
				if err != nil {
					return err
				}
				packageLocation.ColumnStart, err = converter.SafeUIntToInt(startPosition.Column + 1)
				if err != nil {
					return err
				}
				packageLocation.ColumnEnd, err = converter.SafeUIntToInt(endPosition.Column + 1)
				if err != nil {
					return err
				}

				detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID] = append(
					detectionResults[advisoryToCheck.Purl][advisoryToCheck.AdvisoryID],
					models.ReachableSymbolLocation{
						Symbol:          selectorNode.Utf8Text(fileContent),
						PackageLocation: packageLocation,
					})
			}
		}
	}

	return nil
}
