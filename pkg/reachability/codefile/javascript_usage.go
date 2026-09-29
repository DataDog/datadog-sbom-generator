package codefile

import (
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// directSites runs a direct-call/new query (one whose only capture is the called/instantiated
// identifier itself) and returns every match as a callSite, unfiltered against any advisory.
// Shared by directCalls and directNews, which only differ in which query/capture-index to use.
func directSites(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor, query *treesitter.Query, identifierCaptureIdx uint) []callSite {
	var results []callSite

	matches := queryCursor.Matches(query, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		for _, capture := range match.Captures {
			if capture.Index == uint32(identifierCaptureIdx) { //nolint:gosec
				results = append(results, callSite{
					identifierText: capture.Node.Utf8Text(fileContent),
					node:           capture.Node,
				})
			}
		}
	}

	return results
}

// memberSites runs a member-call/new query (object + identifier + whole-selector captures) and
// returns every match as a callSite, unfiltered against any advisory. Shared by memberCalls and
// memberNews, which only differ in which query/capture-indices to use.
func memberSites(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor, query *treesitter.Query, objectCaptureIdx, identifierCaptureIdx, selectorCaptureIdx uint) []callSite {
	var results []callSite

	matches := queryCursor.Matches(query, tree.RootNode(), fileContent)
	for match := matches.Next(); match != nil; match = matches.Next() {
		var objectText, identifierText string
		var selectorNode treesitter.Node

		for _, capture := range match.Captures {
			switch capture.Index {
			case uint32(objectCaptureIdx): //nolint:gosec
				objectText = capture.Node.Utf8Text(fileContent)
			case uint32(identifierCaptureIdx): //nolint:gosec
				identifierText = capture.Node.Utf8Text(fileContent)
			case uint32(selectorCaptureIdx): //nolint:gosec
				selectorNode = capture.Node
			}
		}

		results = append(results, callSite{
			objectText:     objectText,
			identifierText: identifierText,
			node:           selectorNode,
		})
	}

	return results
}

// directCalls returns every direct call site (fn(...)) in the tree, unfiltered against any
// advisory - e.g. for Named/Default function bindings. Each callSite's node is the called
// identifier itself.
func (g *jsGrammar) directCalls(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	return directSites(tree, fileContent, queryCursor, g.directCallQuery, g.directCallFnCaptureIdx)
}

// memberCalls returns every member call site (ns.fn(...)) in the tree, unfiltered - e.g. for
// Namespace function bindings. Each callSite's node is the whole selector expression
// (ns.fn), not just the property, so recorded matches show the full call-site text.
func (g *jsGrammar) memberCalls(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	return memberSites(tree, fileContent, queryCursor, g.memberCallQuery,
		g.memberCallPkgCaptureIdx, g.memberCallFnCaptureIdx, g.memberCallSelectorCaptureIdx)
}

// directNews returns every direct `new` expression (new X(...)) in the tree, unfiltered - e.g.
// for Named/Default class bindings.
func (g *jsGrammar) directNews(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	return directSites(tree, fileContent, queryCursor, g.directNewQuery, g.directNewClassCaptureIdx)
}

// memberNews returns every member `new` expression (new ns.X(...)) in the tree, unfiltered -
// e.g. for Namespace class bindings. Each callSite's node is the whole selector expression
// (ns.X), not just the property.
func (g *jsGrammar) memberNews(tree *treesitter.Tree, fileContent []byte, queryCursor *treesitter.QueryCursor) []callSite {
	return memberSites(tree, fileContent, queryCursor, g.memberNewQuery,
		g.memberNewPkgCaptureIdx, g.memberNewClassCaptureIdx, g.memberNewSelectorCaptureIdx)
}
