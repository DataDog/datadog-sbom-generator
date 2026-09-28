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
