package codefile

import (
	"context"
	"fmt"
	"path/filepath"

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
// (also with let/var). The `#eq?` predicate on @_require restricts matches to calls whose
// function is literally named "require" - without it, any `const x = someOtherFn('str')` call
// would be treated as a require (go-tree-sitter auto-applies text predicates like #eq? during
// QueryCursor.Matches/Captures, so this alone is sufficient; no manual filtering needed in Go).
// Only a plain string-literal argument is matched (`arguments: (arguments (string ...))`); a
// computed argument (`require(variableName)`) or any template-string argument
// (`require(\`pkg\`)`, with or without interpolation) simply doesn't match this query shape at
// all, so no binding is produced for either - both are out of scope, mirroring Go's dot-import
// exclusion. As with the ESM query, destructured names are captured via a nested pattern so
// multiple properties in one object pattern produce separate, correctly-paired matches.
const tsQueryForCJSRequire = `
(variable_declarator
  name: (identifier) @default
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments (string (string_fragment) @path)))
  (#eq? @_require "require"))

(variable_declarator
  name: (object_pattern
    [(shorthand_property_identifier_pattern) @named
     (pair_pattern
       key: (property_identifier) @named
       value: (identifier) @namedAlias)])
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments (string (string_fragment) @path)))
  (#eq? @_require "require"))
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

// Detect resolves every ESM/CJS binding in the file, then for each advisory symbol checks the
// resolved bindings for the symbol's package against the matching usage-query shape (direct or
// member, decided per-binding by its Kind, not by the symbol's type - see the binding-kind
// dispatch table in the doc comments on javascript_bindings.go and the design writeup in
// docs/reachability-js-ts-proposal.md).
func (r *ReachabilityJavaScript) Detect(ctx context.Context, dir string, path string, detectionResults models.DetectionResults, advisoriesToCheck []models.AdvisoryToCheck) error {
	if len(advisoriesToCheck) == 0 {
		return nil
	}

	grammar := r.extensionToGrammar(filepath.Ext(path))
	if grammar == nil {
		// Shouldn't happen: reachability.go only dispatches extensions registered in
		// extensionToLanguageKey, all of which extensionToGrammar recognizes. Guard anyway
		// rather than panic on a nil grammar.
		return nil
	}

	fileContent, err := readFileContent(path)
	if err != nil {
		return err
	}

	tree := parseFile(ctx, grammar.parser, fileContent)
	defer tree.Close()

	// One cursor, reused sequentially across the binding queries and (lazily) the usage
	// queries - matches the existing Java detector's precedent of reusing a single
	// QueryCursor across different Query objects within one Detect() call.
	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()

	bindings := grammar.resolveESMBindings(tree, fileContent, queryCursor)
	grammar.resolveCJSBindings(tree, fileContent, queryCursor, bindings)

	cache := newUsageQueryCache(
		func() []callSite { return grammar.directCalls(tree, fileContent, queryCursor) },
		func() []callSite { return grammar.memberCalls(tree, fileContent, queryCursor) },
		func() []callSite { return grammar.directNews(tree, fileContent, queryCursor) },
		func() []callSite { return grammar.memberNews(tree, fileContent, queryCursor) },
	)

	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			if s.Type != symbolTypeFunction && s.Type != symbolTypeClass {
				r.reporter.Warnf("No JavaScript/TypeScript detection support for symbol type %s", s.Type)
				continue
			}

			packageBindingsForSymbol, ok := bindings[s.Value]
			if !ok {
				continue
			}

			for _, binding := range packageBindingsForSymbol {
				candidates, matchName := r.candidatesForBinding(cache, binding, s)

				for _, candidate := range candidates {
					if !matchesCandidate(candidate, binding, matchName) {
						continue
					}

					packageLocation, err := buildPackageLocation(dir, path, candidate.node.StartPosition(), candidate.node.EndPosition())
					if err != nil {
						return err
					}

					recordMatch(detectionResults, advisoryToCheck.Purl, advisoryToCheck.AdvisoryID, candidate.node.Utf8Text(fileContent), packageLocation)
				}
			}
		}
	}

	return nil
}

// candidatesForBinding picks the usage-query shape to check for one resolved binding, based on
// the binding's Kind and the symbol's Type, and returns the name that candidate call/new sites
// must match:
//   - Named binding:     direct shape; matchName is the advisory symbol's Name. matchesCandidate
//     compares it against binding.exportName (not the local alias) - the
//     symbol's Name must equal what this binding actually exports.
//   - Default binding:   direct shape; matchName is empty - a package has exactly one default
//     export, so any direct call/new through this binding's localName
//     already unambiguously refers to it, regardless of what Name string the
//     advisory data attached (see the doc comment above matchesCandidate for
//     the accepted risk this implies).
//   - Namespace binding: member shape; matchName is the advisory symbol's Name itself (the
//     member/property actually accessed must match it).
func (r *ReachabilityJavaScript) candidatesForBinding(cache *usageQueryCache, binding resolvedBinding, s models.Symbols) ([]callSite, string) {
	switch {
	case binding.kind == bindingNamed && s.Type == symbolTypeFunction:
		return cache.DirectCalls(), s.Name
	case binding.kind == bindingDefault && s.Type == symbolTypeFunction:
		return cache.DirectCalls(), ""
	case binding.kind == bindingNamespace && s.Type == symbolTypeFunction:
		return cache.MemberCalls(), s.Name
	case binding.kind == bindingNamed && s.Type == symbolTypeClass:
		return cache.DirectNews(), s.Name
	case binding.kind == bindingDefault && s.Type == symbolTypeClass:
		return cache.DirectNews(), ""
	case binding.kind == bindingNamespace && s.Type == symbolTypeClass:
		return cache.MemberNews(), s.Name
	default:
		return nil, ""
	}
}

// matchesCandidate reports whether one candidate call/new site actually matches the given
// binding and expected name (matchName - the advisory symbol's Name, or empty for Default
// bindings; see candidatesForBinding).
//
// For direct (Named/Default) candidates, matching requires candidate.identifierText to equal
// binding.localName; for Named bindings, matchName (the advisory symbol's Name) must also equal
// binding.exportName (what this binding actually exports, not its local alias). For Default
// bindings the caller passes an empty matchName, so no Name comparison happens at all here: any
// direct call/new through that localName matches. This is a known, accepted risk documented in
// candidatesForBinding - if a package ever has two distinct function-type advisory symbols (one
// truly about its default export, one about an unrelated named export) in the same file that
// also has a Default binding, both would match a direct call through that binding. This mirrors
// the level of precision already accepted in Go/Java's existing detectors (e.g. Java's
// wildcard-import gap) and is left as-is pending real backend data confirming whether
// Default-export advisories ever coexist with same-package named-export advisories in practice.
//
// For member (Namespace) candidates, matching requires both candidate.objectText to equal
// binding.localName AND candidate.identifierText (the accessed property) to equal matchName.
func matchesCandidate(candidate callSite, binding resolvedBinding, matchName string) bool {
	if binding.kind == bindingNamespace {
		return candidate.objectText == binding.localName && candidate.identifierText == matchName
	}

	if candidate.identifierText != binding.localName {
		return false
	}

	if binding.kind == bindingNamed {
		return matchName == binding.exportName
	}

	return true // bindingDefault: localName match alone is sufficient
}
