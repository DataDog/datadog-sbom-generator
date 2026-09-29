package codefile

import (
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// directCalls returns every direct call site (fn(...)) in the tree, unfiltered against any
// advisory - e.g. for Named/Default function bindings. Each callSite's node is the called
// identifier itself.
func (g *jsGrammar) directCalls(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	var results []callSite

	matches := queryCursor.Matches(g.directCallQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		for _, capture := range match.Captures {
			if capture.Index == uint32(g.directCallFnCaptureIdx) { //nolint:gosec
				results = append(results, callSite{
					identifierText: capture.Node.Utf8Text(fileContent),
					node:           capture.Node,
				})
			}
		}
	}

	return results
}

// memberCalls returns every member call site (ns.fn(...)) in the tree, unfiltered - e.g. for
// Namespace function bindings. Each callSite's node is the whole selector expression
// (ns.fn), not just the property, so recorded matches show the full call-site text.
func (g *jsGrammar) memberCalls(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	var results []callSite

	matches := queryCursor.Matches(g.memberCallQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var pkgText, fnText string
		var selectorNode treesitter.Node

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(g.memberCallPkgCaptureIdx): //nolint:gosec
				pkgText = capture.Node.Utf8Text(fileContent)
			case uint32(g.memberCallFnCaptureIdx): //nolint:gosec
				fnText = capture.Node.Utf8Text(fileContent)
			case uint32(g.memberCallSelectorCaptureIdx): //nolint:gosec
				selectorNode = capture.Node
			}
		}

		results = append(results, callSite{
			objectText:     pkgText,
			identifierText: fnText,
			node:           selectorNode,
		})
	}

	return results
}

// directNews returns every direct `new` expression (new X(...)) in the tree, unfiltered - e.g.
// for Named/Default class bindings.
func (g *jsGrammar) directNews(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	var results []callSite

	matches := queryCursor.Matches(g.directNewQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		for _, capture := range match.Captures {
			if capture.Index == uint32(g.directNewClassCaptureIdx) { //nolint:gosec
				results = append(results, callSite{
					identifierText: capture.Node.Utf8Text(fileContent),
					node:           capture.Node,
				})
			}
		}
	}

	return results
}

// memberNews returns every member `new` expression (new ns.X(...)) in the tree, unfiltered -
// e.g. for Namespace class bindings. Each callSite's node is the whole selector expression
// (ns.X), not just the property.
func (g *jsGrammar) memberNews(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	var results []callSite

	matches := queryCursor.Matches(g.memberNewQuery, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var pkgText, classText string
		var selectorNode treesitter.Node

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(g.memberNewPkgCaptureIdx): //nolint:gosec
				pkgText = capture.Node.Utf8Text(fileContent)
			case uint32(g.memberNewClassCaptureIdx): //nolint:gosec
				classText = capture.Node.Utf8Text(fileContent)
			case uint32(g.memberNewSelectorCaptureIdx): //nolint:gosec
				selectorNode = capture.Node
			}
		}

		results = append(results, callSite{
			objectText:     pkgText,
			identifierText: classText,
			node:           selectorNode,
		})
	}

	return results
}
