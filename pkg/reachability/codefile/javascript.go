package codefile

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	tree_sitter_typescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

// symbolTypeClass is the JS/TS "class" symbol type. symbolTypeFunction (the other symbol type
// this detector understands) is already declared in golang.go and reused as-is here, since both
// detectors share the same package and the same meaning for that constant.
//
// Unlike Go/Java, both symbol types are matched against every binding kind (Named, Default, or
// Namespace) resolved for the advisory's package in a given file; which usage-query shape
// (direct call/new vs. member call/new) applies is decided per-binding, not by the symbol
// type itself.
const symbolTypeClass = "class"

// ESM import query: matches `import { a, b as c } from 'pkg'`, `import def from 'pkg'`, and
// `import * as ns from 'pkg'`. Named import specifiers are captured via a separate pattern
// nested one level deeper than the default/namespace pattern; this lets tree-sitter yield one
// match per specifier (correctly pairing each @named with its own @namedAlias) instead of one
// match per import statement with ambiguous multi-capture grouping. Both patterns still always
// capture the module path via @path. Verified against the real tree-sitter-javascript and
// tree-sitter-typescript grammars: the same query text compiles and matches identically against
// all three (JS, TypeScript, TSX).
const tsQueryForESMImports = `
(import_statement
  (import_clause
    (identifier)? @default
    (namespace_import (identifier) @namespace)?)
  source: (string (string_fragment) @path))

(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @named
        alias: (identifier)? @namedAlias)))
  source: (string (string_fragment) @path))
`

// CJS require query: matches `const pkg = require('pkg')` and `const { a, b: c } = require('pkg')`
// (also with let/var). Only a plain string-literal argument is matched (`arguments: (arguments
// (string ...))`); a computed argument (`require(variableName)`) or any template-string argument
// (`require(\`pkg\`)`, with or without interpolation) simply doesn't match this query shape at
// all, so no binding is produced for either - both are out of scope, mirroring Go's dot-import
// exclusion. As with the ESM query, destructured names are captured via a nested pattern so
// multiple properties in one object pattern produce separate, correctly-paired matches.
const tsQueryForCJSRequire = `
(variable_declarator
  name: (identifier) @default
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments (string (string_fragment) @path))))

(variable_declarator
  name: (object_pattern
    [(shorthand_property_identifier_pattern) @named
     (pair_pattern
       key: (property_identifier) @named
       value: (identifier) @namedAlias)])
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments (string (string_fragment) @path))))
`

// Usage queries: one direct-call/new shape and one member-call/new shape per symbol type
// (function vs. class). Which one applies to a given advisory symbol is decided per-binding at
// match time (Named/Default -> direct, Namespace -> member), not by the symbol type.
const (
	tsQueryForDirectCall = `(call_expression function: (identifier) @fn)`
	tsQueryForMemberCall = `
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @fn) @selector)
`
	tsQueryForDirectNew = `(new_expression constructor: (identifier) @class)`
	tsQueryForMemberNew = `
(new_expression
  constructor: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @class) @selector)
`
)

// jsGrammar holds one grammar's parser, its compiled queries, and the resolved capture indices
// needed to read those queries' results. One instance exists per grammar (JS, TypeScript, TSX);
// all three compile the exact same query text, since the ESM/CJS/call/new node shapes are
// identical across all three grammars.
type jsGrammar struct {
	parser *treesitter.Parser

	esmImportQuery  *treesitter.Query
	cjsRequireQuery *treesitter.Query
	directCallQuery *treesitter.Query
	memberCallQuery *treesitter.Query
	directNewQuery  *treesitter.Query
	memberNewQuery  *treesitter.Query

	esmDefaultCaptureIdx    uint
	esmNamespaceCaptureIdx  uint
	esmNamedCaptureIdx      uint
	esmNamedAliasCaptureIdx uint
	esmPathCaptureIdx       uint

	cjsDefaultCaptureIdx    uint
	cjsNamedCaptureIdx      uint
	cjsNamedAliasCaptureIdx uint
	cjsPathCaptureIdx       uint

	directCallFnCaptureIdx uint

	memberCallPkgCaptureIdx      uint
	memberCallFnCaptureIdx       uint
	memberCallSelectorCaptureIdx uint

	directNewClassCaptureIdx uint

	memberNewPkgCaptureIdx      uint
	memberNewClassCaptureIdx    uint
	memberNewSelectorCaptureIdx uint
}

// close releases this grammar's parser and all its compiled queries.
func (g *jsGrammar) close() {
	g.parser.Close()
	g.esmImportQuery.Close()
	g.cjsRequireQuery.Close()
	g.directCallQuery.Close()
	g.memberCallQuery.Close()
	g.directNewQuery.Close()
	g.memberNewQuery.Close()
}

// newJSGrammar compiles a full grammar set (parser + all 6 queries + capture indices) for one
// tree-sitter Language.
func newJSGrammar(language *treesitter.Language) (*jsGrammar, error) {
	parser := treesitter.NewParser()
	if err := parser.SetLanguage(language); err != nil {
		return nil, fmt.Errorf("failed to set tree-sitter language on parser: %w", err)
	}

	esmImportQuery, err := treesitter.NewQuery(language, tsQueryForESMImports)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for ESM imports: %w", err)
	}

	cjsRequireQuery, err := treesitter.NewQuery(language, tsQueryForCJSRequire)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for CJS require: %w", err)
	}

	directCallQuery, err := treesitter.NewQuery(language, tsQueryForDirectCall)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for direct calls: %w", err)
	}

	memberCallQuery, err := treesitter.NewQuery(language, tsQueryForMemberCall)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for member calls: %w", err)
	}

	directNewQuery, err := treesitter.NewQuery(language, tsQueryForDirectNew)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for direct news: %w", err)
	}

	memberNewQuery, err := treesitter.NewQuery(language, tsQueryForMemberNew)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for member news: %w", err)
	}

	esmDefaultCaptureIdx, _ := esmImportQuery.CaptureIndexForName("default")
	esmNamespaceCaptureIdx, _ := esmImportQuery.CaptureIndexForName("namespace")
	esmNamedCaptureIdx, _ := esmImportQuery.CaptureIndexForName("named")
	esmNamedAliasCaptureIdx, _ := esmImportQuery.CaptureIndexForName("namedAlias")
	esmPathCaptureIdx, _ := esmImportQuery.CaptureIndexForName("path")

	cjsDefaultCaptureIdx, _ := cjsRequireQuery.CaptureIndexForName("default")
	cjsNamedCaptureIdx, _ := cjsRequireQuery.CaptureIndexForName("named")
	cjsNamedAliasCaptureIdx, _ := cjsRequireQuery.CaptureIndexForName("namedAlias")
	cjsPathCaptureIdx, _ := cjsRequireQuery.CaptureIndexForName("path")

	directCallFnCaptureIdx, _ := directCallQuery.CaptureIndexForName("fn")

	memberCallPkgCaptureIdx, _ := memberCallQuery.CaptureIndexForName("pkg")
	memberCallFnCaptureIdx, _ := memberCallQuery.CaptureIndexForName("fn")
	memberCallSelectorCaptureIdx, _ := memberCallQuery.CaptureIndexForName("selector")

	directNewClassCaptureIdx, _ := directNewQuery.CaptureIndexForName("class")

	memberNewPkgCaptureIdx, _ := memberNewQuery.CaptureIndexForName("pkg")
	memberNewClassCaptureIdx, _ := memberNewQuery.CaptureIndexForName("class")
	memberNewSelectorCaptureIdx, _ := memberNewQuery.CaptureIndexForName("selector")

	return &jsGrammar{
		parser: parser,

		esmImportQuery:  esmImportQuery,
		cjsRequireQuery: cjsRequireQuery,
		directCallQuery: directCallQuery,
		memberCallQuery: memberCallQuery,
		directNewQuery:  directNewQuery,
		memberNewQuery:  memberNewQuery,

		esmDefaultCaptureIdx:    esmDefaultCaptureIdx,
		esmNamespaceCaptureIdx:  esmNamespaceCaptureIdx,
		esmNamedCaptureIdx:      esmNamedCaptureIdx,
		esmNamedAliasCaptureIdx: esmNamedAliasCaptureIdx,
		esmPathCaptureIdx:       esmPathCaptureIdx,

		cjsDefaultCaptureIdx:    cjsDefaultCaptureIdx,
		cjsNamedCaptureIdx:      cjsNamedCaptureIdx,
		cjsNamedAliasCaptureIdx: cjsNamedAliasCaptureIdx,
		cjsPathCaptureIdx:       cjsPathCaptureIdx,

		directCallFnCaptureIdx: directCallFnCaptureIdx,

		memberCallPkgCaptureIdx:      memberCallPkgCaptureIdx,
		memberCallFnCaptureIdx:       memberCallFnCaptureIdx,
		memberCallSelectorCaptureIdx: memberCallSelectorCaptureIdx,

		directNewClassCaptureIdx: directNewClassCaptureIdx,

		memberNewPkgCaptureIdx:      memberNewPkgCaptureIdx,
		memberNewClassCaptureIdx:    memberNewClassCaptureIdx,
		memberNewSelectorCaptureIdx: memberNewSelectorCaptureIdx,
	}, nil
}

// ReachabilityJavaScript detects reachable vulnerable symbols in JavaScript/TypeScript source
// files. It holds one jsGrammar per tree-sitter grammar (JavaScript, TypeScript, TSX) and
// dispatches to the right one per file based on extension.
type ReachabilityJavaScript struct {
	jsGrammar  *jsGrammar // .js, .jsx, .mjs, .cjs
	tsGrammar  *jsGrammar // .ts, .mts, .cts
	tsxGrammar *jsGrammar // .tsx

	reporter reporter.Reporter
}

// extensionToGrammar returns the grammar set to use for a file extension (as returned by
// filepath.Ext, including the leading dot), or nil if the extension isn't recognized.
func (r *ReachabilityJavaScript) extensionToGrammar(ext string) *jsGrammar {
	switch ext {
	case ".js", ".jsx", ".mjs", ".cjs":
		return r.jsGrammar
	case ".ts", ".mts", ".cts":
		return r.tsGrammar
	case ".tsx":
		return r.tsxGrammar
	default:
		return nil
	}
}

// NewJavaScriptReachableDetector creates a new ReachabilityJavaScript instance that once
// instantiated can be used to parse JavaScript/TypeScript/TSX files. You should call Close() on
// the instance once you're finished parsing.
func NewJavaScriptReachableDetector(r reporter.Reporter) (*ReachabilityJavaScript, error) {
	jsLanguage := treesitter.NewLanguage(tree_sitter_javascript.Language())
	tsLanguage := treesitter.NewLanguage(tree_sitter_typescript.LanguageTypescript())
	tsxLanguage := treesitter.NewLanguage(tree_sitter_typescript.LanguageTSX())

	jsGrammar, err := newJSGrammar(jsLanguage)
	if err != nil {
		return nil, fmt.Errorf("failed to set up JavaScript grammar: %w", err)
	}

	tsGrammar, err := newJSGrammar(tsLanguage)
	if err != nil {
		jsGrammar.close()
		return nil, fmt.Errorf("failed to set up TypeScript grammar: %w", err)
	}

	tsxGrammar, err := newJSGrammar(tsxLanguage)
	if err != nil {
		jsGrammar.close()
		tsGrammar.close()
		return nil, fmt.Errorf("failed to set up TSX grammar: %w", err)
	}

	return &ReachabilityJavaScript{
		jsGrammar:  jsGrammar,
		tsGrammar:  tsGrammar,
		tsxGrammar: tsxGrammar,
		reporter:   reporter.Effective(r),
	}, nil
}

// Close closes all hanging tree-sitter related resources across all three grammars.
// This should only be called once you're finished parsing all JavaScript/TypeScript files.
func (r *ReachabilityJavaScript) Close() {
	r.jsGrammar.close()
	r.tsGrammar.close()
	r.tsxGrammar.close()
}

// Detect is a temporary no-op placeholder: it reports no reachable symbols for any file. The
// grammars, queries, and capture indices are already fully set up (see NewJavaScriptReachableDetector);
// only the binding-resolution and matching logic that consumes them is still to come.
func (r *ReachabilityJavaScript) Detect(_ context.Context, _ string, _ string, _ models.DetectionResults, _ []models.AdvisoryToCheck) error {
	return nil
}
