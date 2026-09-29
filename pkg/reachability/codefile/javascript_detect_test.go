package codefile

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:paralleltest
func Test_Detect_JavaScript_NoAdvisories(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	detectionResults := models.DetectionResults{}

	err = detector.Detect(context.Background(), ".", "testdata/CVE-2025-9012/named-import/app.js", detectionResults, []models.AdvisoryToCheck{})

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

// Test_Detect_JavaScript_FunctionSymbolFound covers every binding shape (ESM named/aliased/
// default/namespace, CJS namespace/default-callable/destructured) that resolves to a
// symbolTypeFunction match, asserting the exact matched Symbol text and 1-based line/column
// range for each - mirroring Test_Detect_Go_FunctionSymbolFound's convention.
//
//nolint:paralleltest
func Test_Detect_JavaScript_FunctionSymbolFound(t *testing.T) {
	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
		},
		{
			Purl:       "pkg:npm/minimist@1.2.0",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "minimist", Name: "minimist"}},
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
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
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
// symbolTypeClass match: ESM named import, ESM namespace import, and CJS require, each
// instantiated via `new`.
//
//nolint:paralleltest
func Test_Detect_JavaScript_ClassSymbolFound(t *testing.T) {
	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/vulnerable-lib@1.0.0",
			AdvisoryID: "CVE-2025-9012",
			Symbols:    []models.Symbols{{Type: symbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
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
		"cjs require, member instantiation": {
			path:           "testdata/CVE-2025-9012/class-require/app.js",
			expectedSymbol: "pkg.Client",
			lineStart:      2, lineEnd: 2, columnStart: 15, columnEnd: 25,
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
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
// package with the same symbol name, a computed require (no binding produced at all), a
// function name mismatch, and a class name mismatch - the last two are regression fixtures for
// the candidatesForBinding/matchesCandidate tautology bug caught during development.
//
//nolint:paralleltest
func Test_Detect_JavaScript_NoMatch(t *testing.T) {
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
					Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"computed require produces no binding": {
			path: "testdata/CVE-2025-9012/computed-require-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"function name mismatch": {
			path: "testdata/CVE-2025-9012/function-name-mismatch-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/lodash@4.17.19",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
				},
			},
		},
		"class name mismatch": {
			path: "testdata/CVE-2025-9012/class-name-mismatch-notresolved/app.js",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:npm/vulnerable-lib@1.0.0",
					AdvisoryID: "CVE-2025-9012",
					Symbols:    []models.Symbols{{Type: symbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
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

			detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
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
// different binding kinds across two files, both correctly attributed to the same advisory from
// one Symbols entry.
//
//nolint:paralleltest
func Test_Detect_JavaScript_SameSymbolReachableMultipleWays(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-2020-8203",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "zipObjectDeep"}},
		},
	}

	paths := []string{
		"testdata/CVE-2020-8203/namespace-require/app.js",
		"testdata/CVE-2020-8203/esm-named-import/app.js",
	}

	detectionResults := models.DetectionResults{}
	for _, path := range paths {
		err := detector.Detect(context.Background(), ".", path, detectionResults, advisoriesToCheck)
		require.NoError(t, err)
	}

	require.Len(t, detectionResults, 1)
	locations := detectionResults["pkg:npm/lodash@4.17.19"]["CVE-2020-8203"]
	require.Len(t, locations, 2)

	byFile := make(map[string]models.ReachableSymbolLocation, 2)
	for _, loc := range locations {
		byFile[loc.Filename] = loc
	}

	namespaceMatch := byFile["testdata/CVE-2020-8203/namespace-require/app.js"]
	assert.Equal(t, "_.zipObjectDeep", namespaceMatch.Symbol)
	assert.Equal(t, 2, namespaceMatch.LineStart)
	assert.Equal(t, 1, namespaceMatch.ColumnStart)
	assert.Equal(t, 16, namespaceMatch.ColumnEnd)

	namedImportMatch := byFile["testdata/CVE-2020-8203/esm-named-import/app.js"]
	assert.Equal(t, "zipObjectDeep", namedImportMatch.Symbol)
	assert.Equal(t, 2, namedImportMatch.LineStart)
	assert.Equal(t, 1, namedImportMatch.ColumnStart)
	assert.Equal(t, 14, namedImportMatch.ColumnEnd)
}

// Test_Detect_TypeScriptAndTSX confirms grammar dispatch works correctly for .ts and .tsx
// files, including a .tsx file that mixes class instantiation with JSX syntax in the same file.
//
//nolint:paralleltest
func Test_Detect_TypeScriptAndTSX(t *testing.T) {
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
					Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
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
					Symbols:    []models.Symbols{{Type: symbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
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
			detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
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
