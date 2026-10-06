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

// CJS require query: matches `const pkg = require('pkg')`, destructured
// `const { a, b: c } = require('pkg')`, and a single export selected straight off the require
// result - `const merge = require('pkg').merge` or `const merge = require('pkg')['merge']`
// (also let/var); `#eq?` restricts matches to calls literally named "require".
//
// CJS has no namespace syntax like ESM's `import * as ns`, so the plain-identifier form only
// captures @default; resolveCJSBindings turns it into both a Namespace and a Default binding,
// since we can't tell which one it is until we see how it's actually called.
//
// The property-selected form binds exactly one export under the declarator's name, which is the
// same thing destructuring does, so it's recorded as a Named binding: @named is the exported
// name (the property) and @namedAlias is the local name (the declarator), which is how
// resolveCJSBindings already distinguishes `{ a: b }` from `{ a }` - no extra Go logic needed.
// The dot and subscript spellings are separate patterns rather than one alternation because each
// has to respell the whole require-call object anyway, so alternating would cost readability
// without saving anything. A computed subscript (`require('pkg')[name]`) is excluded by anchoring
// the index to a literal string: the selected export isn't knowable from the source, the same
// reason require(variable) is excluded.
//
// The leading `.` anchor matches only the first argument, mirroring require(id):
// require('lodash', x) binds "lodash", require(x, 'lodash') binds nothing, and
// require('a', 'b') binds only "a" - extra string arguments are never alternate paths. A
// computed or template-string first argument produces no match, out of scope like Go's
// dot-import exclusion.
const tsQueryForCJSRequire = `
(variable_declarator
  name: (identifier) @default
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments . (string (string_fragment) @path)))
  (#eq? @_require "require"))

(variable_declarator
  name: (object_pattern
    [(shorthand_property_identifier_pattern) @named
     (pair_pattern
       key: (property_identifier) @named
       value: (identifier) @namedAlias)])
  value: (call_expression
    function: (identifier) @_require
    arguments: (arguments . (string (string_fragment) @path)))
  (#eq? @_require "require"))

(variable_declarator
  name: (identifier) @namedAlias
  value: (member_expression
    object: (call_expression
      function: (identifier) @_require
      arguments: (arguments . (string (string_fragment) @path)))
    property: (property_identifier) @named)
  (#eq? @_require "require"))

(variable_declarator
  name: (identifier) @namedAlias
  value: (subscript_expression
    object: (call_expression
      function: (identifier) @_require
      arguments: (arguments . (string (string_fragment) @path)))
    index: (string (string_fragment) @named))
  (#eq? @_require "require"))
`

// Inline require member-call query: matches `require('pkg').fn(...)` and
// `require('pkg')['fn'](...)` - a call on a property of a require() result with no intervening
// variable, e.g. the common Node idiom require('fs').readFileSync(...). No binding exists to
// resolve here, so Detect matches these straight against the advisory: @path is the package and
// @fn is the symbol.
//
// There's no `new` counterpart because JS doesn't spell one the obvious way:
// `new require('pkg').C()` parses as `(new require('pkg')).C()`, which constructs the module
// itself rather than C. Only `new (require('pkg').C)()` would, and that form is rare enough not
// to carry its own query.
const tsQueryForInlineRequireCall = `
(call_expression
  function: (member_expression
    object: (call_expression
      function: (identifier) @_require
      arguments: (arguments . (string (string_fragment) @path)))
    property: (property_identifier) @fn) @selector
  (#eq? @_require "require"))

(call_expression
  function: (subscript_expression
    object: (call_expression
      function: (identifier) @_require
      arguments: (arguments . (string (string_fragment) @path)))
    index: (string (string_fragment) @fn)) @selector
  (#eq? @_require "require"))
`

// Inline require callable query: matches `require('pkg')(...)` - the require() result invoked
// directly, with no property access and no intervening variable, as a default-callable package
// is used. The outer call's function is the require() call itself rather than a member
// expression, which is why the member-call query above cannot reach this shape.
//
// @selector is the require() call, so a recorded match points at the callee rather than the
// invocation's arguments, matching the member-call convention.
//
// There is no capture for the symbol: nothing in this shape names an export. Detect therefore
// requires the advisory's Name to equal the package name; see the inline-callable loop there.
//
// No `new` counterpart: `new require('pkg')()` parses as `(new require('pkg'))()`, which treats
// require itself as the constructor and throws at runtime, so there is nothing to match.
const tsQueryForInlineRequireCallable = `
(call_expression
  function: (call_expression
    function: (identifier) @_require
    arguments: (arguments . (string (string_fragment) @path))) @selector
  (#eq? @_require "require"))
`

// Usage queries: one direct-call/new shape and one member-call/new shape per symbol type
// (function vs. class). Which one applies to a given advisory symbol is decided per-binding at
// match time (Named/Default -> direct, Namespace -> member), not by the symbol type.
//
// Each member shape has a dot-notation and a bracket-notation pattern: ns.fn(...) and
// ns['fn'](...) are the same statically-resolvable access, so both reuse the same captures and
// nothing downstream needs to know which one matched.
//
// The index is anchored to a literal string. Computed and template-literal indexes produce no
// match, since the accessed name isn't knowable from the source. Optional chaining still matches:
// tree-sitter matches children non-exhaustively, so the extra optional_chain node is ignored.
const (
	tsQueryForDirectCall = `(call_expression function: (identifier) @fn)`
	tsQueryForMemberCall = `
(call_expression
  function: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @fn) @selector)

(call_expression
  function: (subscript_expression
    object: (identifier) @pkg
    index: (string (string_fragment) @fn)) @selector)
`
	tsQueryForDirectNew = `(new_expression constructor: (identifier) @class)`
	tsQueryForMemberNew = `
(new_expression
  constructor: (member_expression
    object: (identifier) @pkg
    property: (property_identifier) @class) @selector)

(new_expression
  constructor: (subscript_expression
    object: (identifier) @pkg
    index: (string (string_fragment) @class)) @selector)
`
)

// Capture names used by the queries above. Both newJSGrammar's spec list and the use sites
// reference these constants rather than bare string literals, so a mistyped capture name is a
// compile error instead of a map miss resolving to index 0 (a valid index, which would make the
// mistake look like "this query matched nothing"). The constant values must match the @names in
// the query text; newCompiledQuery verifies that at construction.
const (
	captureDefault    = "default"
	captureNamespace  = "namespace"
	captureNamed      = "named"
	captureNamedAlias = "namedAlias"
	capturePath       = "path"
	captureFn         = "fn"
	capturePkg        = "pkg"
	captureClass      = "class"
	captureSelector   = "selector"
)

// compiledQuery pairs a compiled tree-sitter query with its capture-name -> index map, both
// resolved once at construction. Use sites look captures up by name instead of the grammar
// carrying a separate index field per capture, and the uint32 conversion that
// treesitter.QueryCapture.Index comparisons need happens here rather than at every use site.
type compiledQuery struct {
	query    *treesitter.Query
	captures map[string]uint32
}

// capture returns the index tree-sitter assigned to a capture name. Pass one of the capture*
// constants; those are the names newJSGrammar registers, and newCompiledQuery rejects any that
// the query text doesn't define.
func (q *compiledQuery) capture(name string) uint32 {
	return q.captures[name]
}

func (q *compiledQuery) close() {
	q.query.Close()
}

// newCompiledQuery compiles queryText and resolves every name in captureNames to its index.
// A name the compiled query doesn't define is a programming error - the query text and the
// expected capture list have drifted - so it fails here instead of silently resolving to index
// 0, which is itself a valid index and would make the mismatch look like "found no matches".
func newCompiledQuery(language *treesitter.Language, label string, queryText string, captureNames ...string) (*compiledQuery, error) {
	query, err := treesitter.NewQuery(language, queryText)
	if err != nil {
		return nil, fmt.Errorf("failed to create tree-sitter query for %s: %w", label, err)
	}

	captures := make(map[string]uint32, len(captureNames))
	for _, name := range captureNames {
		idx, ok := query.CaptureIndexForName(name)
		if !ok {
			query.Close()

			return nil, fmt.Errorf("tree-sitter query for %s has no capture named %q", label, name)
		}

		captures[name] = uint32(idx) //nolint:gosec
	}

	return &compiledQuery{query: query, captures: captures}, nil
}

// jsGrammar holds one grammar's parser and its compiled queries. One instance exists per
// grammar (JS, TypeScript, TSX); all three compile the exact same query text, since the
// ESM/CJS/call/new node shapes are identical across all three grammars.
type jsGrammar struct {
	parser *treesitter.Parser

	esmImportQuery             *compiledQuery
	cjsRequireQuery            *compiledQuery
	directCallQuery            *compiledQuery
	memberCallQuery            *compiledQuery
	directNewQuery             *compiledQuery
	memberNewQuery             *compiledQuery
	inlineRequireCallQuery     *compiledQuery
	inlineRequireCallableQuery *compiledQuery
}

// close releases this grammar's parser and every compiled query it holds. Safe to call on a
// partially-constructed grammar, so newJSGrammar can use it as its single cleanup path.
func (g *jsGrammar) close() {
	if g.parser != nil {
		g.parser.Close()
	}

	for _, q := range []*compiledQuery{
		g.esmImportQuery, g.cjsRequireQuery,
		g.directCallQuery, g.memberCallQuery,
		g.directNewQuery, g.memberNewQuery,
		g.inlineRequireCallQuery, g.inlineRequireCallableQuery,
	} {
		if q != nil {
			q.close()
		}
	}
}

// newJSGrammar compiles a full grammar set (parser + all 6 queries, each with its capture
// indices resolved) for one tree-sitter Language. The spec list below is the single source of
// truth for which captures each query is expected to define.
func newJSGrammar(language *treesitter.Language) (*jsGrammar, error) {
	parser := treesitter.NewParser()
	if err := parser.SetLanguage(language); err != nil {
		parser.Close()

		return nil, fmt.Errorf("failed to set tree-sitter language on parser: %w", err)
	}

	g := &jsGrammar{parser: parser}

	for _, spec := range []struct {
		dest         **compiledQuery
		label        string
		text         string
		captureNames []string
	}{
		{&g.esmImportQuery, "ESM imports", tsQueryForESMImports, []string{captureDefault, captureNamespace, captureNamed, captureNamedAlias, capturePath}},
		{&g.cjsRequireQuery, "CJS require", tsQueryForCJSRequire, []string{captureDefault, captureNamed, captureNamedAlias, capturePath}},
		{&g.directCallQuery, "direct calls", tsQueryForDirectCall, []string{captureFn}},
		{&g.memberCallQuery, "member calls", tsQueryForMemberCall, []string{capturePkg, captureFn, captureSelector}},
		{&g.directNewQuery, "direct news", tsQueryForDirectNew, []string{captureClass}},
		{&g.memberNewQuery, "member news", tsQueryForMemberNew, []string{capturePkg, captureClass, captureSelector}},
		{&g.inlineRequireCallQuery, "inline require calls", tsQueryForInlineRequireCall, []string{capturePath, captureFn, captureSelector}},
		{&g.inlineRequireCallableQuery, "inline require callable", tsQueryForInlineRequireCallable, []string{capturePath, captureSelector}},
	} {
		query, err := newCompiledQuery(language, spec.label, spec.text, spec.captureNames...)
		if err != nil {
			g.close()

			return nil, err
		}

		*spec.dest = query
	}

	return g, nil
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
		func() []callSite { return grammar.inlineRequireCalls(tree, fileContent, queryCursor) },
		func() []callSite { return grammar.inlineRequireCallableCalls(tree, fileContent, queryCursor) },
	)

	for _, advisoryToCheck := range advisoriesToCheck {
		for _, s := range advisoryToCheck.Symbols {
			if s.Type != SymbolTypeFunction && s.Type != SymbolTypeClass {
				r.reporter.Warnf("No JavaScript/TypeScript detection support for symbol type %s", s.Type)
				continue
			}

			// Inline require calls (require('pkg').fn(...)) bind nothing, so they're matched on
			// the call site's own package path instead of a resolved binding, and before the
			// bindings lookup below - which would otherwise skip the file entirely when the
			// package is never bound to a local name. Function symbols only; see
			// tsQueryForInlineRequireCall for why there's no `new` equivalent.
			if s.Type == SymbolTypeFunction {
				for _, candidate := range cache.InlineRequireCalls() {
					if candidate.objectText != s.Value || candidate.identifierText != s.Name {
						continue
					}

					if err := recordCandidate(detectionResults, advisoryToCheck, dir, path, fileContent, candidate.node); err != nil {
						return err
					}
				}

				// An inline callable require names no export, so there is no accessed property
				// to compare. The advisory's Name must equal the package itself, which is how a
				// default export is identified - the same check matchesCandidate applies to a
				// bound Default binding. Without it, require('lodash')([1,2,3]) would match every
				// function-type lodash advisory.
				if s.Name == s.Value {
					for _, candidate := range cache.InlineRequireCallableCalls() {
						if candidate.objectText != s.Value {
							continue
						}

						if err := recordCandidate(detectionResults, advisoryToCheck, dir, path, fileContent, candidate.node); err != nil {
							return err
						}
					}
				}
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

					if err := recordCandidate(detectionResults, advisoryToCheck, dir, path, fileContent, candidate.node); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// recordCandidate records one matched call/new site as a reachable symbol for the advisory,
// resolving the node's position into a package location first.
func recordCandidate(detectionResults models.DetectionResults, advisoryToCheck models.AdvisoryToCheck, dir string, path string, fileContent []byte, node treesitter.Node) error {
	packageLocation, err := buildPackageLocation(dir, path, node.StartPosition(), node.EndPosition())
	if err != nil {
		return err
	}

	recordMatch(detectionResults, advisoryToCheck.Purl, advisoryToCheck.AdvisoryID, node.Utf8Text(fileContent), packageLocation)

	return nil
}

// candidatesForBinding picks which cached usage-query result to check for one resolved binding,
// and the name candidates must match: for Named bindings, the advisory symbol's Name (checked
// against binding.exportName in matchesCandidate); for Default bindings, empty (matchesCandidate
// compares it against the binding's local name); for Namespace bindings, the advisory symbol's
// Name itself (checked against the accessed property).
func (r *ReachabilityJavaScript) candidatesForBinding(cache *usageQueryCache, binding resolvedBinding, s models.Symbols) ([]callSite, string) {
	switch {
	case binding.kind == bindingNamed && s.Type == SymbolTypeFunction:
		return cache.DirectCalls(), s.Name
	case binding.kind == bindingDefault && s.Type == SymbolTypeFunction:
		return cache.DirectCalls(), s.Name
	case binding.kind == bindingNamespace && s.Type == SymbolTypeFunction:
		return cache.MemberCalls(), s.Name
	case binding.kind == bindingNamed && s.Type == SymbolTypeClass:
		return cache.DirectNews(), s.Name
	case binding.kind == bindingDefault && s.Type == SymbolTypeClass:
		return cache.DirectNews(), s.Name
	case binding.kind == bindingNamespace && s.Type == SymbolTypeClass:
		return cache.MemberNews(), s.Name
	default:
		return nil, ""
	}
}

// matchesCandidate reports whether one candidate call/new site matches the given binding and
// expected name (matchName - the advisory symbol's Name; see candidatesForBinding).
//
// Direct (Named/Default) candidates must have identifierText equal to binding.localName. Named
// bindings additionally require matchName == binding.exportName (what the binding actually
// exports, not its local alias). Default bindings require matchName == binding.localName: a
// default import/require binds the whole module under a name the developer chose freely, so the
// only signal available that an advisory is actually about the default export is its Name lining
// up with that local name (e.g. `import minimist from 'minimist'` against an advisory naming
// "minimist").
//
// Accepting a Default binding without that name check would be actively wrong: many modules are
// simultaneously callable and property-bearing, so `const _ = require('lodash'); _([1,2,3])`
// (idiomatic lodash chaining, which never touches `merge`) would falsely match every
// function-type lodash advisory. The trade-off is a false negative when a default import is
// aliased away from the advisory's name (`import parseArgs from 'minimist'`), which is the right
// direction to err for an analysis whose purpose is reducing vulnerability noise.
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

	return matchName == binding.localName // bindingDefault
}
