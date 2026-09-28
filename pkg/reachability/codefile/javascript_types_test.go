package codefile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_usageQueryCache_ComputesLazilyAndOnlyOnce verifies that each of the four usage-query
// shapes is computed at most once per cache instance, no matter how many times its getter is
// called - the core "check if it's there, compute only if not" behavior the cache exists for.
func Test_usageQueryCache_ComputesLazilyAndOnlyOnce(t *testing.T) {
	t.Parallel()

	directCallsCalls := 0
	memberCallsCalls := 0
	directNewsCalls := 0
	memberNewsCalls := 0

	cache := newUsageQueryCache(
		func() []callSite {
			directCallsCalls++
			return []callSite{{identifierText: "directCall"}}
		},
		func() []callSite {
			memberCallsCalls++
			return []callSite{{objectText: "ns", identifierText: "memberCall"}}
		},
		func() []callSite {
			directNewsCalls++
			return []callSite{{identifierText: "DirectNew"}}
		},
		func() []callSite {
			memberNewsCalls++
			return []callSite{{objectText: "ns", identifierText: "MemberNew"}}
		},
	)

	// None of the compute functions should have run yet - laziness means nothing is computed
	// until it's actually requested.
	assert.Equal(t, 0, directCallsCalls)
	assert.Equal(t, 0, memberCallsCalls)
	assert.Equal(t, 0, directNewsCalls)
	assert.Equal(t, 0, memberNewsCalls)

	// Call each getter twice; the underlying compute function should only run on the first
	// call for each shape.
	for range 2 {
		assert.Equal(t, []callSite{{identifierText: "directCall"}}, cache.DirectCalls())
	}
	for range 2 {
		assert.Equal(t, []callSite{{objectText: "ns", identifierText: "memberCall"}}, cache.MemberCalls())
	}
	for range 2 {
		assert.Equal(t, []callSite{{identifierText: "DirectNew"}}, cache.DirectNews())
	}
	for range 2 {
		assert.Equal(t, []callSite{{objectText: "ns", identifierText: "MemberNew"}}, cache.MemberNews())
	}

	assert.Equal(t, 1, directCallsCalls, "DirectCalls() should only compute once")
	assert.Equal(t, 1, memberCallsCalls, "MemberCalls() should only compute once")
	assert.Equal(t, 1, directNewsCalls, "DirectNews() should only compute once")
	assert.Equal(t, 1, memberNewsCalls, "MemberNews() should only compute once")
}

// Test_usageQueryCache_EmptyResultIsStillCached verifies that a compute function returning an
// empty (but non-nil-conceptually) result is still correctly treated as "already computed" on
// subsequent calls, not re-run. This exercises the nil-pointer-vs-computed-empty-slice
// distinction the cache relies on for its laziness check.
func Test_usageQueryCache_EmptyResultIsStillCached(t *testing.T) {
	t.Parallel()

	calls := 0
	cache := newUsageQueryCache(
		func() []callSite {
			calls++
			return []callSite{}
		},
		func() []callSite { return nil },
		func() []callSite { return nil },
		func() []callSite { return nil },
	)

	first := cache.DirectCalls()
	second := cache.DirectCalls()

	assert.Empty(t, first)
	assert.Empty(t, second)
	assert.Equal(t, 1, calls, "an empty result should still only be computed once")
}

// Test_usageQueryCache_IndependentShapes verifies that requesting one shape doesn't trigger
// computation of the others - only the shapes actually needed by the caller's advisories
// should ever run their query.
func Test_usageQueryCache_IndependentShapes(t *testing.T) {
	t.Parallel()

	memberCallsCalls := 0
	otherCalls := 0

	cache := newUsageQueryCache(
		func() []callSite { otherCalls++; return nil },
		func() []callSite { memberCallsCalls++; return []callSite{{identifierText: "merge", objectText: "_"}} },
		func() []callSite { otherCalls++; return nil },
		func() []callSite { otherCalls++; return nil },
	)

	cache.MemberCalls()

	assert.Equal(t, 1, memberCallsCalls)
	assert.Equal(t, 0, otherCalls, "requesting MemberCalls should not compute DirectCalls, DirectNews, or MemberNews")
}
