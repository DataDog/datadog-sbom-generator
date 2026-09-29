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

// symbolTypeClass is the JS/TS "class" symbol type; symbolTypeFunction (declared in golang.go,
// reused here since both detectors share this package) is the other. Unlike Go/Java, both types
// are matched against every binding kind (Named, Default, Namespace) resolved for a symbol's
// package - the binding kind, not the symbol type, decides direct vs. member matching.
const symbolTypeClass = "class"

// ESM import query: matches `import { a, b as c } from 'pkg'`, `import def from 'pkg'`, and
// `import * as ns from 'pkg'`. Named specifiers are captured via a separate pattern nested one
// level deeper than the default/namespace pattern, so tree-sitter yields one match per
// specifier (correctly pairing each @named with its own @namedAlias) instead of one ambiguous
// multi-capture match per statement. Compiles identically against JS, TypeScript, and TSX.
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

// CJS require query: matches `const pkg = require('pkg')` and destructured
// `const { a, b: c } = require('pkg')` (also let/var). The `#eq?` predicate restricts matches to
// calls literally named "require" (go-tree-sitter auto-applies text predicates like #eq?, so no
// manual filtering is needed in Go). Only a plain string-literal path is matched; a computed
// (`require(variableName)`) or template-string argument produces no match at all, keeping both
// out of scope - mirroring Go's dot-import exclusion. Destructured names use the same
// nested-pattern trick as the ESM query, so multiple properties produce separate matches.
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
// resolved bindings for the symbol's package against the matching usage-query shape - decided
// per-binding by its Kind, not by the symbol's type (see candidatesForBinding).
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

// candidatesForBinding picks which cached usage-query result to check for one resolved binding,
// and the name candidates must match: for Named bindings, the advisory symbol's Name (checked
// against binding.exportName in matchesCandidate); for Default bindings, empty (matchesCandidate
// skips the name check entirely); for Namespace bindings, the advisory symbol's Name itself
// (checked against the accessed property).
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

// matchesCandidate reports whether one candidate call/new site matches the given binding and
// expected name (matchName; see candidatesForBinding).
//
// Direct (Named/Default) candidates must have identifierText equal to binding.localName; Named
// bindings additionally require matchName == binding.exportName (what the binding actually
// exports, not its local alias). Default bindings skip the name check entirely - a package has
// exactly one default export, so a direct call/new through its localName already unambiguously
// refers to it. Known accepted risk: if a package ever has two distinct function-type advisories
// in the same file (one about its default export, one about an unrelated named export) with a
// Default binding present, both would match - the same class of imprecision already accepted
// elsewhere (e.g. Java's wildcard-import gap).
//
// Member (Namespace) candidates require both objectText == binding.localName and
// identifierText (the accessed property) == matchName.
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
