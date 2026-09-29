package codefile

import (
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// resolveESMBindings walks all ESM import statements in the parsed tree and returns a map of
// npm package name -> local bindings created for that package in this file.
//
// Handles, per import statement:
//   - default import:              import def from 'pkg'              -> bindingDefault
//   - namespace import:            import * as ns from 'pkg'          -> bindingNamespace
//   - named import (incl. alias):  import { fn, fn2 as f2 } from 'pkg' -> bindingNamed (one per specifier)
//   - combined default+namespace:  import def, * as ns from 'pkg'     -> both bindings recorded
//   - combined default+named:      import def, { fn } from 'pkg'      -> both bindings recorded
//
// Known accepted gap: `import type { X } from 'pkg'` and `import { type X } from 'pkg'`
// (TypeScript/TSX only - JS grammar can't parse this at all) are NOT filtered out. The
// "type" keyword is an anonymous token that doesn't change the import_statement/import_clause/
// import_specifier node shape this query matches against, so a type-only import still produces
// a binding in the table even though it has no runtime effect. This is only a false-positive
// risk if the same file also has an unrelated runtime symbol that happens to share the same
// name - the same category of accepted risk as Java's wildcard-import gap and Go's dot-import
// exclusion (see docs/reachability-analysis-investigation.md).
func (g *jsGrammar) resolveESMBindings(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) packageBindings {
	bindings := make(packageBindings)

	matches := queryCursor.Matches(g.esmImportQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var defaultText, namespaceText, namedText, namedAliasText, pathText string

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(g.esmDefaultCaptureIdx): //nolint:gosec
				defaultText = capture.Node.Utf8Text(fileContent)
			case uint32(g.esmNamespaceCaptureIdx): //nolint:gosec
				namespaceText = capture.Node.Utf8Text(fileContent)
			case uint32(g.esmNamedCaptureIdx): //nolint:gosec
				namedText = capture.Node.Utf8Text(fileContent)
			case uint32(g.esmNamedAliasCaptureIdx): //nolint:gosec
				namedAliasText = capture.Node.Utf8Text(fileContent)
			case uint32(g.esmPathCaptureIdx): //nolint:gosec
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
			bindings[pathText] = append(bindings[pathText], resolvedBinding{
				localName: defaultText,
				kind:      bindingDefault,
			})
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
// namespace object with methods (`x.fn()`, e.g. most libraries) or as a directly-callable
// default export (`x()`, e.g. minimist). Since CJS has no separate syntax for "this is a
// namespace" vs "this is a default export" the way ESM does (import * as ns vs import def),
// both possibilities are recorded as separate bindings for the same localName: one
// bindingNamespace and one bindingDefault. This isn't a workaround for uncertainty - it's
// correct: many packages are simultaneously callable AND expose properties (e.g. jQuery's
// `$(...)`), so checking both usage shapes against the actual call sites in the file is the
// right behavior regardless. No false positives result from having both present, since a match
// still requires an actual call site of that specific shape (direct or member) referencing this
// exact localName and the advisory's symbol name - an unused binding kind just never matches
// anything.
//
// Computed require arguments (require(variableName)) and any template-string require argument
// (require(`pkg`), interpolated or not) produce zero matches from cjsRequireQuery itself, so no
// binding is ever created for either - both are out of scope, mirroring Go's dot-import
// exclusion. See the query's own doc comment in javascript.go for how that's enforced by the
// query shape alone.
func (g *jsGrammar) resolveCJSBindings(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor, bindings packageBindings) {
	matches := queryCursor.Matches(g.cjsRequireQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var defaultText, namedText, namedAliasText, pathText string

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(g.cjsDefaultCaptureIdx): //nolint:gosec
				defaultText = capture.Node.Utf8Text(fileContent)
			case uint32(g.cjsNamedCaptureIdx): //nolint:gosec
				namedText = capture.Node.Utf8Text(fileContent)
			case uint32(g.cjsNamedAliasCaptureIdx): //nolint:gosec
				namedAliasText = capture.Node.Utf8Text(fileContent)
			case uint32(g.cjsPathCaptureIdx): //nolint:gosec
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
