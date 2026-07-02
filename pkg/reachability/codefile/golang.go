package codefile

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_go "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

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

func (r *ReachabilityGo) Detect(_ context.Context, _ string, _ string, _ models.DetectionResults, _ []models.AdvisoryToCheck) error {
	return nil
}
