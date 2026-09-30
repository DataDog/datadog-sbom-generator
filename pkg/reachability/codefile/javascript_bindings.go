package codefile

import (
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// bindingKind describes how a package/module was bound to a local identifier in a JS/TS file.
type bindingKind int

const (
	// bindingNamed is a binding that refers to one specific exported symbol directly, e.g.
	// `import { fn } from 'pkg'` or `const { fn } = require('pkg')`. Call sites reference it
	// as a bare identifier: fn(...).
	bindingNamed bindingKind = iota
	// bindingDefault is a binding to a package's default export, e.g. `import fn from 'pkg'`
	// or `const fn = require('pkg')`. Call sites reference it as a bare identifier: fn(...).
	bindingDefault
	// bindingNamespace is a binding to an entire package/module object, e.g.
	// `import * as ns from 'pkg'` or `const ns = require('pkg')`. Call sites reference
	// exported symbols via property access: ns.fn(...).
	bindingNamespace
)

// resolvedBinding is one local identifier bound to a package/module in a single file, along
// with enough information to match it against a vulnerable symbol's advisory data.
type resolvedBinding struct {
	// localName is the identifier used at call sites in this file (after any "as" alias).
	localName string
	// kind determines which usage-query shape (direct call vs. member call) applies to this
	// binding.
	kind bindingKind
	// exportName is the original exported name before any "as" alias was applied. It's only
	// meaningful for bindingNamed; bindingDefault and bindingNamespace bindings don't have a
	// separate export name to match against; they're always matched by localName instead.
	exportName string
}

// packageBindings maps an npm package name to every binding resolved for it in one file. A
// package can have multiple bindings in the same file (e.g. required twice under different
// local names, or imported both as a namespace and destructured).
type packageBindings map[string][]resolvedBinding

// resolveESMBindings walks all ESM import statements in the parsed tree and returns a map of
// npm package name -> local bindings created for that package in this file.
//
// Handles, per import statement:
//   - default import:              import def from 'pkg'              -> bindingDefault + bindingNamespace
//   - namespace import:            import * as ns from 'pkg'          -> bindingNamespace
//   - named import (incl. alias):  import { fn, fn2 as f2 } from 'pkg' -> bindingNamed (one per specifier)
//   - combined default+namespace:  import def, * as ns from 'pkg'     -> both bindings recorded
//   - combined default+named:      import def, { fn } from 'pkg'      -> both bindings recorded
//
// A default import records both kinds for the same local name, for the same reason
// resolveCJSBindings does it for `const x = require('pkg')`: the binding is ambiguous. Most of
// npm is CommonJS, and under esModuleInterop `import x from 'cjs-pkg'` resolves to the whole
// module.exports - so `x` may be called directly (x(...), e.g. minimist) or used as a namespace
// (x.fn(...), e.g. lodash), and which one is only knowable from the call sites. Recording both
// is not a false-positive risk: a Default binding only matches a direct call when the advisory's
// Name equals the local name, and a Namespace binding only matches a member call when the
// accessed property equals it, so an inapplicable kind simply never matches anything.
//
// Known accepted gap: `import type { X } from 'pkg'` and `import { type X } from 'pkg'`
// (TypeScript/TSX only) are NOT filtered out - the "type" keyword doesn't change the AST shape
// this query matches against, so a type-only import still produces a binding despite having no
// runtime effect. Only a false-positive risk if the file also has an unrelated runtime symbol
// with the same name - the same category of risk as Java's wildcard-import gap.
func (g *jsGrammar) resolveESMBindings(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) packageBindings {
	bindings := make(packageBindings)

	var (
		defaultIdx    = g.esmImportQuery.capture(captureDefault)
		namespaceIdx  = g.esmImportQuery.capture(captureNamespace)
		namedIdx      = g.esmImportQuery.capture(captureNamed)
		namedAliasIdx = g.esmImportQuery.capture(captureNamedAlias)
		pathIdx       = g.esmImportQuery.capture(capturePath)
	)

	matches := queryCursor.Matches(g.esmImportQuery.query, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var defaultText, namespaceText, namedText, namedAliasText, pathText string

		for _, capture := range match.Captures {
			switch capture.Index {
			case defaultIdx:
				defaultText = capture.Node.Utf8Text(fileContent)
			case namespaceIdx:
				namespaceText = capture.Node.Utf8Text(fileContent)
			case namedIdx:
				namedText = capture.Node.Utf8Text(fileContent)
			case namedAliasIdx:
				namedAliasText = capture.Node.Utf8Text(fileContent)
			case pathIdx:
				pathText = capture.Node.Utf8Text(fileContent)
			}
		}

		if pathText == "" {
			// @path is a required capture in both patterns; this should never happen, but
			// there's nothing useful to record without a package name.
			continue
		}

		// A single match can carry both @default and @namespace at once (e.g.
		// `import def, * as ns from 'pkg'`), so these are independent checks, not a
		// mutually-exclusive switch - both bindings must be recorded when both are present.
		if defaultText != "" {
			bindings[pathText] = append(bindings[pathText],
				resolvedBinding{localName: defaultText, kind: bindingDefault},
				resolvedBinding{localName: defaultText, kind: bindingNamespace},
			)
		}
		if namespaceText != "" {
			bindings[pathText] = append(bindings[pathText], resolvedBinding{
				localName: namespaceText,
				kind:      bindingNamespace,
			})
		}
		if namedText != "" {
			localName := namedText
			if namedAliasText != "" {
				localName = namedAliasText
			}
			bindings[pathText] = append(bindings[pathText], resolvedBinding{
				localName:  localName,
				kind:       bindingNamed,
				exportName: namedText,
			})
		}
	}

	return bindings
}

// resolveCJSBindings walks all `require(...)` calls in the parsed tree and merges the bindings
// they create into the given packageBindings map (which may already contain ESM bindings from
// resolveESMBindings for the same file - CJS bindings for a package are appended alongside any
// existing entries for that same package, not replacing them).
//
// Handles, per require call:
//   - plain identifier:  const x = require('pkg')            -> ambiguous, see below
//   - destructured:      const { a, b: c } = require('pkg')  -> bindingNamed (one per property)
//
// The plain-identifier form is structurally ambiguous in CJS: `x` could be used later as a
// namespace object with methods (`x.fn()`) or as a directly-callable default export (`x()`,
// e.g. minimist) - CJS has no separate syntax for the two the way ESM does (import * as ns vs
// import def). Both possibilities are recorded as separate bindings for the same localName
// (bindingNamespace and bindingDefault); this is correct, not a workaround, since some packages
// are genuinely both callable and property-bearing. No false-positive risk from recording both:
// a match still requires an actual call site of that specific shape, so an unused binding kind
// just never matches anything.
//
// Computed (require(variableName)) and template-string require arguments produce zero matches
// from cjsRequireQuery itself, so no binding is ever created for either - both are out of scope,
// mirroring Go's dot-import exclusion.
func (g *jsGrammar) resolveCJSBindings(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor, bindings packageBindings) {
	var (
		defaultIdx    = g.cjsRequireQuery.capture(captureDefault)
		namedIdx      = g.cjsRequireQuery.capture(captureNamed)
		namedAliasIdx = g.cjsRequireQuery.capture(captureNamedAlias)
		pathIdx       = g.cjsRequireQuery.capture(capturePath)
	)

	matches := queryCursor.Matches(g.cjsRequireQuery.query, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var defaultText, namedText, namedAliasText, pathText string

		for _, capture := range match.Captures {
			switch capture.Index {
			case defaultIdx:
				defaultText = capture.Node.Utf8Text(fileContent)
			case namedIdx:
				namedText = capture.Node.Utf8Text(fileContent)
			case namedAliasIdx:
				namedAliasText = capture.Node.Utf8Text(fileContent)
			case pathIdx:
				pathText = capture.Node.Utf8Text(fileContent)
			}
		}

		if pathText == "" {
			// @path is a required capture in both patterns; this should never happen, but
			// there's nothing useful to record without a package name.
			continue
		}

		if defaultText != "" {
			bindings[pathText] = append(bindings[pathText],
				resolvedBinding{localName: defaultText, kind: bindingNamespace},
				resolvedBinding{localName: defaultText, kind: bindingDefault},
			)
		}
		if namedText != "" {
			localName := namedText
			if namedAliasText != "" {
				localName = namedAliasText
			}
			bindings[pathText] = append(bindings[pathText], resolvedBinding{
				localName:  localName,
				kind:       bindingNamed,
				exportName: namedText,
			})
		}
	}
}
