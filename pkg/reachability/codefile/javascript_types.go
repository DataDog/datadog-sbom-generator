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
// bindings. The underlying query runs at most once per cache instance.
func (c *usageQueryCache) DirectCalls() []callSite {
	if c.directCalls == nil {
		result := c.computeDirectCalls()
		c.directCalls = &result
	}
	return *c.directCalls
}

// MemberCalls returns every member call site (ns.fn(...)) in the file, e.g. for Namespace
// bindings. The underlying query runs at most once per cache instance.
func (c *usageQueryCache) MemberCalls() []callSite {
	if c.memberCalls == nil {
		result := c.computeMemberCalls()
		c.memberCalls = &result
	}
	return *c.memberCalls
}

// DirectNews returns every direct `new` expression (new X(...)) in the file, e.g. for
// Named/Default bindings. The underlying query runs at most once per cache instance.
func (c *usageQueryCache) DirectNews() []callSite {
	if c.directNews == nil {
		result := c.computeDirectNews()
		c.directNews = &result
	}
	return *c.directNews
}

// MemberNews returns every member `new` expression (new ns.X(...)) in the file, e.g. for
// Namespace bindings. The underlying query runs at most once per cache instance.
func (c *usageQueryCache) MemberNews() []callSite {
	if c.memberNews == nil {
		result := c.computeMemberNews()
		c.memberNews = &result
	}
	return *c.memberNews
}
