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
// (TypeScript/TSX only) are NOT filtered out - the "type" keyword doesn't change the AST shape
// this query matches against, so a type-only import still produces a binding despite having no
// runtime effect. Only a false-positive risk if the file also has an unrelated runtime symbol
// with the same name - the same category of risk as Java's wildcard-import gap.
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
