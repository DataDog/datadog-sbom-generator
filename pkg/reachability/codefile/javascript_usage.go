package codefile

import (
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

// callSite is one candidate call or `new` expression captured by a usage query, before it's
// been filtered against any specific advisory symbol.
type callSite struct {
	// identifierText is the called/instantiated identifier's text: the bare identifier for a
	// direct call/new (fn(...), new X(...)), or the property identifier for a member
	// call/new (ns.fn(...), new ns.X(...)).
	identifierText string
	// objectText is the object/namespace identifier's text for a member call/new
	// (ns.fn(...), new ns.X(...)). It's empty for direct calls/news, which have no object.
	objectText string
	// node is the node whose position should be recorded in a match: the whole member
	// expression for member calls/news, or the identifier itself for direct calls/news.
	node treesitter.Node
}

// usageQueryCache lazily computes and caches the four usage-query shapes (function-direct,
// function-member, class-direct, class-member) for one file. Each shape is computed at most
// once per file, on first request, regardless of how many advisories/symbols end up needing
// it; the cache should be discarded once the file it was created for has been fully processed.
//
// Each compute function is expected to run its tree-sitter query once against the file's tree
// and return every candidate call site found, unfiltered; the caller is responsible for
// filtering the cached results against specific advisory symbols.
type usageQueryCache struct {
	computeDirectCalls func() []callSite
	computeMemberCalls func() []callSite
	computeDirectNews  func() []callSite
	computeMemberNews  func() []callSite

	// A nil pointer means "not yet computed"; a non-nil pointer (even to an empty slice)
	// means the query has already run and this is its result.
	directCalls *[]callSite
	memberCalls *[]callSite
	directNews  *[]callSite
	memberNews  *[]callSite
}

// newUsageQueryCache creates a usageQueryCache for one file. None of the compute functions run
// until their corresponding getter is first called.
func newUsageQueryCache(
	computeDirectCalls func() []callSite,
	computeMemberCalls func() []callSite,
	computeDirectNews func() []callSite,
	computeMemberNews func() []callSite,
) *usageQueryCache {
	return &usageQueryCache{
		computeDirectCalls: computeDirectCalls,
		computeMemberCalls: computeMemberCalls,
		computeDirectNews:  computeDirectNews,
		computeMemberNews:  computeMemberNews,
	}
}

// DirectCalls returns every direct call site (fn(...)) in the file, e.g. for Named/Default
// bindings.
func (c *usageQueryCache) DirectCalls() []callSite {
	if c.directCalls == nil {
		result := c.computeDirectCalls()
		c.directCalls = &result
	}

	return *c.directCalls
}

// MemberCalls returns every member call site (ns.fn(...)) in the file, e.g. for Namespace
// bindings.
func (c *usageQueryCache) MemberCalls() []callSite {
	if c.memberCalls == nil {
		result := c.computeMemberCalls()
		c.memberCalls = &result
	}

	return *c.memberCalls
}

// DirectNews returns every direct `new` expression (new X(...)) in the file, e.g. for
// Named/Default bindings.
func (c *usageQueryCache) DirectNews() []callSite {
	if c.directNews == nil {
		result := c.computeDirectNews()
		c.directNews = &result
	}

	return *c.directNews
}

// MemberNews returns every member `new` expression (new ns.X(...)) in the file, e.g. for
// Namespace bindings.
func (c *usageQueryCache) MemberNews() []callSite {
	if c.memberNews == nil {
		result := c.computeMemberNews()
		c.memberNews = &result
	}

	return *c.memberNews
}

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
