package javascript

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reachability/codefile"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

//nolint:paralleltest
func Test_Detect_JavaScript_NoAdvisories(t *testing.T) {
	detector, err := NewDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	detectionResults := models.DetectionResults{}

	err = detector.Detect(context.Background(), ".", "testdata/CVE-2025-9012/named-import/app.js", detectionResults, []models.AdvisoryToCheck{})

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

// Test_Detect_JavaScript_FunctionSymbolFound covers every binding shape (ESM named/aliased/
// default/namespace, CJS namespace/default-callable/destructured) that resolves to a
// codefile.SymbolTypeFunction match, asserting the exact matched Symbol text and 1-based line/column
// range for each - mirroring Test_Detect_Go_FunctionSymbolFound's convention.
func Test_Detect_JavaScript_FunctionSymbolFound(t *testing.T) {
	t.Parallel()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
		},
		{
			Purl:       "pkg:npm/minimist@1.2.0",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "minimist", Name: "minimist"}},
		},
	}

	fixtures := map[string]struct {
		path           string
		purl           string
		expectedSymbol string
		lineStart      int
		lineEnd        int
		columnStart    int
		columnEnd      int
	}{
		"named import, direct call": {
			path:           "testdata/CVE-2025-9012/named-import/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 6,
		},
		"aliased named import, direct call": {
			path:           "testdata/CVE-2025-9012/named-import-aliased/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "m",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 2,
		},
		// A property selected directly off a require() result binds that one export under the
		// declarator's name, so it's a Named binding reached by a direct call - the same shape
		// as `const { merge } = require("lodash")`, just written as a property access.
		"require property access, direct call": {
			path:           "testdata/CVE-2025-9012/require-property-dot/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 6,
		},
		"require property access aliased, direct call": {
			path:           "testdata/CVE-2025-9012/require-property-aliased/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "m",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 2,
		},
		"require property access via string subscript, direct call": {
			path:           "testdata/CVE-2025-9012/require-property-bracket/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 6,
		},
		// No local binding at all: the package and the symbol both come straight from the call
		// site, e.g. the common Node idiom require("fs").readFileSync(...).
		"inline require member call, no binding": {
			path:           "testdata/CVE-2025-9012/require-inline-member-call/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: `require("lodash").merge`,
			lineStart:      1, lineEnd: 1, columnStart: 1, columnEnd: 24,
		},
		"default import, direct call": {
			path:           "testdata/CVE-2025-9012/default-import/app.js",
			purl:           "pkg:npm/minimist@1.2.0",
			expectedSymbol: "minimist",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 9,
		},
		"namespace import, member call": {
			path:           "testdata/CVE-2025-9012/namespace-import/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "_.merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 8,
		},
		// Bracket notation resolves identically to dot notation; only the recorded symbol text
		// differs.
		"namespace import, bracket-notation member call": {
			path:           "testdata/CVE-2025-9012/namespace-import-bracket-call/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: `_["merge"]`,
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 11,
		},
		// An optional_chain node between the object and the index must not prevent a match.
		"namespace import, optional-chained bracket member call": {
			path:           "testdata/CVE-2025-9012/namespace-import-optional-bracket-call/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: `_?.["merge"]`,
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 13,
		},
		"inline require member call, bracket notation": {
			path:           "testdata/CVE-2025-9012/require-inline-member-call-bracket/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: `require("lodash")["merge"]`,
			lineStart:      1, lineEnd: 1, columnStart: 1, columnEnd: 27,
		},
		// The require() result invoked directly, with no property access and no binding. The
		// recorded symbol is the callee, not the invocation.
		"inline require callable, no binding": {
			path:           "testdata/CVE-2025-9012/require-inline-callable/app.js",
			purl:           "pkg:npm/minimist@1.2.0",
			expectedSymbol: `require("minimist")`,
			lineStart:      1, lineEnd: 1, columnStart: 1, columnEnd: 20,
		},
		"cjs namespace require, member call": {
			path:           "testdata/CVE-2025-9012/require-namespace/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "_.merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 8,
		},
		"cjs default-callable require, direct call (minimist-shape)": {
			path:           "testdata/CVE-2025-9012/require-default-callable/app.js",
			purl:           "pkg:npm/minimist@1.2.0",
			expectedSymbol: "minimist",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 9,
		},
		"cjs destructured require, direct call": {
			path:           "testdata/CVE-2025-9012/require-destructured/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 6,
		},
		// A CommonJS package imported with ESM default syntax resolves to the whole
		// module.exports under esModuleInterop, so the binding is usable as a namespace
		// (_.merge(...)) just like `const _ = require('lodash')` is - the single most common
		// way TypeScript code consumes lodash.
		"esm default import, member call (esModuleInterop shape)": {
			path:           "testdata/CVE-2025-9012/default-import-member-call/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "_.merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 8,
		},
		// The inline require on line 3 is matched before the bound `_` calls, so recording order
		// differs from source order: the earliest line must still win.
		"multiple call sites keep only the earliest": {
			path:           "testdata/CVE-2025-9012/multiple-call-sites/app.js",
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "_.merge",
			lineStart:      2, lineEnd: 2, columnStart: 1, columnEnd: 8,
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewDetector(&reporter.VoidReporter{})
			require.NoError(t, err)
			defer detector.Close()

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", tc.path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)

			advisories, ok := detectionResults[tc.purl]
			require.True(t, ok, "expected detection results for purl %s, got %+v", tc.purl, detectionResults)
			reachableSymbols, ok := advisories["CVE-2025-9012"]
			require.True(t, ok)
			require.Len(t, reachableSymbols, 1)

			assert.Equal(t, tc.expectedSymbol, reachableSymbols[0].Symbol)
			assert.Equal(t, tc.path, reachableSymbols[0].Filename)
			assert.Equal(t, tc.lineStart, reachableSymbols[0].LineStart)
			assert.Equal(t, tc.lineEnd, reachableSymbols[0].LineEnd)
			assert.Equal(t, tc.columnStart, reachableSymbols[0].ColumnStart)
			assert.Equal(t, tc.columnEnd, reachableSymbols[0].ColumnEnd)
		})
	}
}

// Test_Detect_JavaScript_ClassSymbolFound covers every binding shape that resolves to a
// codefile.SymbolTypeClass match: ESM named import, ESM namespace import, ESM default import (the
// Default binding kind - previously only verified with an ad hoc throwaway script, now a
// committed regression test), CJS require, and a .jsx file combining a direct instantiation
// with real JSX syntax in the same file (the JS-grammar analog of Test_Detect_TypeScriptAndTSX's
// .tsx case, proving JSX support isn't unique to the TSX grammar). Each instantiated via `new`.
func Test_Detect_JavaScript_ClassSymbolFound(t *testing.T) {
	t.Parallel()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/vulnerable-lib@1.0.0",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: codefile.SymbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
		},
	}

	fixtures := map[string]struct {
		path           string
		expectedSymbol string
		lineStart      int
		lineEnd        int
		columnStart    int
		columnEnd      int
	}{
		"named import, direct instantiation": {
			path:           "testdata/CVE-2025-9012/class-named-import/app.js",
			expectedSymbol: "Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 21,
		},
		"namespace import, member instantiation": {
			path:           "testdata/CVE-2025-9012/class-namespace-import/app.js",
			expectedSymbol: "pkg.Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 25,
		},
		"namespace import, bracket-notation member instantiation": {
			path:           "testdata/CVE-2025-9012/class-namespace-import-bracket-new/app.js",
			expectedSymbol: `pkg["Client"]`,
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 28,
		},
		"cjs require, member instantiation": {
			path:           "testdata/CVE-2025-9012/class-require/app.js",
			expectedSymbol: "pkg.Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 25,
		},
		"default import, direct instantiation (Default binding)": {
			path:           "testdata/CVE-2025-9012/class-default-import/app.js",
			expectedSymbol: "Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 21,
		},
		"jsx file, direct instantiation alongside JSX syntax": {
			path:           "testdata/CVE-2025-9012/jsx-file/app.jsx",
			expectedSymbol: "Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 21,
		},
		// Same esModuleInterop shape as the function case: a default-imported CJS package
		// used as a namespace, with the class reached via property access.
		"default import, member instantiation (esModuleInterop shape)": {
			path:           "testdata/CVE-2025-9012/class-default-import-member-new/app.js",
			expectedSymbol: "pkg.Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 25,
		},
		// Class counterpart of require-property-dot: selecting the constructor off the
		// require() result makes it a Named binding, instantiated directly.
		"require property access, direct instantiation": {
			path:           "testdata/CVE-2025-9012/class-require-property/app.js",
			expectedSymbol: "Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 21,
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewDetector(&reporter.VoidReporter{})
			require.NoError(t, err)
			defer detector.Close()

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", tc.path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)

			advisories, ok := detectionResults["pkg:npm/vulnerable-lib@1.0.0"]
			require.True(t, ok, "expected detection results, got %+v", detectionResults)
			reachableSymbols, ok := advisories["CVE-2025-9012"]
			require.True(t, ok)
			require.Len(t, reachableSymbols, 1)

			assert.Equal(t, tc.expectedSymbol, reachableSymbols[0].Symbol)
			assert.Equal(t, tc.path, reachableSymbols[0].Filename)
			assert.Equal(t, tc.lineStart, reachableSymbols[0].LineStart)
			assert.Equal(t, tc.lineEnd, reachableSymbols[0].LineEnd)
			assert.Equal(t, tc.columnStart, reachableSymbols[0].ColumnStart)
			assert.Equal(t, tc.columnEnd, reachableSymbols[0].ColumnEnd)
		})
	}
}

// Test_Detect_JavaScript_NoMatch covers cases that must NOT produce a match: an unrelated
// package with the same symbol name, a computed require (no binding produced at all), function
// and class name mismatches (regression fixtures for the candidatesForBinding/matchesCandidate
// tautology bug), a default-callable module invoked directly with an unrelated advisory symbol
// (regression fixture for the Default-binding false positive found in review), and an
// unsupported symbol type.
func Test_Detect_JavaScript_NoMatch(t *testing.T) {
	t.Parallel()

	fixtures := map[string]struct {
		path              string
		advisoriesToCheck []models.AdvisoryToCheck
	}{
		"unrelated package with the same symbol name": {
			path: "testdata/CVE-2025-9012/unrelated-package-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"computed require produces no binding": {
			path: "testdata/CVE-2025-9012/computed-require-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"function name mismatch": {
			path: "testdata/CVE-2025-9012/function-name-mismatch-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"class name mismatch": {
			path: "testdata/CVE-2025-9012/class-name-mismatch-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/vulnerable-lib@1.0.0",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
				},
			},
		},
		// Regression test for a real false positive found in review: many modules are both
		// callable and property-bearing, so `const _ = require('lodash'); _([1,2,3])`
		// (idiomatic lodash chaining, which never touches `merge`) must NOT match a
		// function-type advisory for `merge`. Before the fix, Default bindings skipped the
		// name check entirely and this matched every function-type lodash advisory.
		"default-callable module called directly, unrelated advisory symbol": {
			path: "testdata/CVE-2025-9012/default-callable-unrelated-symbol-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		// A computed subscript on a require() result is as unresolvable as require(variable):
		// the selected export name isn't in the source, so no binding may be created.
		"computed subscript on require produces no binding": {
			path: "testdata/CVE-2025-9012/require-property-computed-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		// The binding resolves, but to a different export than the advisory names.
		"require property access, unrelated export name": {
			path: "testdata/CVE-2025-9012/require-property-name-mismatch-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		// An inline callable require names no export, so a match requires the advisory's Name to
		// equal the package. Without that check, this idiomatic lodash chaining - which never
		// touches merge - would match every function-type lodash advisory.
		"inline callable require, unrelated advisory symbol": {
			path: "testdata/CVE-2025-9012/inline-callable-unrelated-symbol-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		// A computed index names nothing knowable from the source.
		"computed bracket index produces no match": {
			path: "testdata/CVE-2025-9012/namespace-import-computed-bracket-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		// Template-literal indexes are out of scope, with or without interpolation.
		"template-literal bracket index produces no match": {
			path: "testdata/CVE-2025-9012/namespace-import-template-bracket-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"unsupported symbol type": {
			path: "testdata/CVE-2025-9012/named-import/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: "some-unsupported-type", Value: "lodash", Name: "merge"}},
				},
			},
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewDetector(reporter.NewMockReporter(gomock.NewController(t)))
			require.NoError(t, err)
			defer detector.Close()

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", tc.path, detectionResults, tc.advisoriesToCheck)
			require.NoError(t, err)
			assert.Empty(t, detectionResults)
		})
	}
}

// Test_Detect_JavaScript_SameSymbolReachableMultipleWays reproduces the CVE-2020-8203 (lodash
// zipObjectDeep) shape from the design doc: the same vulnerable function reached via two
// different binding kinds across two files, each file attributing it to the same advisory from
// one Symbols entry.
//
//nolint:paralleltest
func Test_Detect_JavaScript_SameSymbolReachableMultipleWays(t *testing.T) {
	detector, err := NewDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-2020-8203",
			Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "zipObjectDeep"}},
		},
	}

	expected := map[string]struct {
		symbol                       string
		line, columnStart, columnEnd int
	}{
		"testdata/CVE-2020-8203/namespace-require/app.js": {"_.zipObjectDeep", 2, 1, 16},
		"testdata/CVE-2020-8203/esm-named-import/app.js":  {"zipObjectDeep", 2, 1, 14},
	}

	for path, want := range expected {
		detectionResults := models.DetectionResults{}
		err := detector.Detect(context.Background(), ".", path, detectionResults, advisoriesToCheck)
		require.NoError(t, err)

		locations := detectionResults["pkg:npm/lodash@4.17.19"]["CVE-2020-8203"]
		require.Len(t, locations, 1, path)
		assert.Equal(t, want.symbol, locations[0].Symbol)
		assert.Equal(t, path, locations[0].Filename)
		assert.Equal(t, want.line, locations[0].LineStart)
		assert.Equal(t, want.columnStart, locations[0].ColumnStart)
		assert.Equal(t, want.columnEnd, locations[0].ColumnEnd)
	}
}

// Test_Detect_TypeScriptAndTSX confirms grammar dispatch works correctly for .ts and .tsx
// files, including a .tsx file that mixes class instantiation with JSX syntax in the same file.
func Test_Detect_TypeScriptAndTSX(t *testing.T) {
	t.Parallel()

	fixtures := map[string]struct {
		path              string
		advisoriesToCheck []models.AdvisoryToCheck
		purl              string
		expectedSymbol    string
		columnStart       int
		columnEnd         int
	}{
		"typescript named import": {
			path: "testdata/CVE-2025-9012/typescript-file/app.ts",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
			purl:           "pkg:npm/lodash@4.17.19",
			expectedSymbol: "merge",
			columnStart:    1, columnEnd: 6,
		},
		"tsx class instantiation alongside JSX": {
			path: "testdata/CVE-2025-9012/tsx-file/app.tsx",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/vulnerable-lib@1.0.0",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: codefile.SymbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
				},
			},
			purl:           "pkg:npm/vulnerable-lib@1.0.0",
			expectedSymbol: "Client",
			columnStart:    15, columnEnd: 21,
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// A fresh detector per parallel subtest: tree-sitter's Parser is not safe for
			// concurrent Parse() calls from multiple goroutines, and sharing one detector
			// declared outside this loop would also mean its deferred Close() runs as soon
			// as the parent function body finishes - which happens before these paused
			// t.Parallel() subtests actually execute, closing the parser out from under them.
			detector, err := NewDetector(&reporter.VoidReporter{})
			require.NoError(t, err)
			defer detector.Close()

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", tc.path, detectionResults, tc.advisoriesToCheck)
			require.NoError(t, err)

			advisories, ok := detectionResults[tc.purl]
			require.True(t, ok, "expected detection results, got %+v", detectionResults)
			reachableSymbols, ok := advisories["CVE-2025-9012"]
			require.True(t, ok)
			require.Len(t, reachableSymbols, 1)

			assert.Equal(t, tc.expectedSymbol, reachableSymbols[0].Symbol)
			assert.Equal(t, 2, reachableSymbols[0].LineStart)
			assert.Equal(t, tc.columnStart, reachableSymbols[0].ColumnStart)
			assert.Equal(t, tc.columnEnd, reachableSymbols[0].ColumnEnd)
		})
	}
}
