package javascript

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_javascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

func Test_NewJavaScriptReachableDetector(t *testing.T) {
	t.Parallel()

	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	assert.NotNil(t, detector)
	assert.NotNil(t, detector.jsGrammar)
	assert.NotNil(t, detector.tsGrammar)
	assert.NotNil(t, detector.tsxGrammar)
}

func Test_ReachabilityJavaScript_extensionToGrammar(t *testing.T) {
	t.Parallel()

	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	// t.Cleanup, not defer: this function's subtests call t.Parallel(), which pauses them
	// and returns control to this function immediately - a plain defer would close the
	// detector before the paused subtests actually run. t.Cleanup only runs after every
	// subtest (including parallel ones) has completed.
	t.Cleanup(detector.Close)

	tests := []struct {
		ext      string
		expected *jsGrammar
	}{
		{".js", detector.jsGrammar},
		{".jsx", detector.jsGrammar},
		{".mjs", detector.jsGrammar},
		{".cjs", detector.jsGrammar},
		{".ts", detector.tsGrammar},
		{".mts", detector.tsGrammar},
		{".cts", detector.tsGrammar},
		{".tsx", detector.tsxGrammar},
		{".java", nil},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			t.Parallel()
			assert.Same(t, tt.expected, detector.extensionToGrammar(tt.ext))
		})
	}
}

// Test_NewJavaScriptReachableDetector_QueriesCompileAndCaptureIndicesResolve pins the exact set
// of captures each query resolves, for every grammar. newCompiledQuery already fails loudly if a
// registered capture name doesn't resolve, so NewJavaScriptReachableDetector returning no error
// proves each name resolved; this additionally catches the reverse drift - a query-text change
// that drops, renames, or adds a capture relative to newJSGrammar's spec list - which would
// otherwise silently narrow what the detector can match.
func Test_NewJavaScriptReachableDetector_QueriesCompileAndCaptureIndicesResolve(t *testing.T) {
	t.Parallel()

	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	// t.Cleanup, not defer - see the comment in Test_ReachabilityJavaScript_extensionToGrammar.
	t.Cleanup(detector.Close)

	grammars := map[string]*jsGrammar{
		"js":  detector.jsGrammar,
		"ts":  detector.tsGrammar,
		"tsx": detector.tsxGrammar,
	}

	for name, g := range grammars {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, tc := range []struct {
				queryName string
				query     *compiledQuery
				captures  []string
			}{
				{"esmImport", g.esmImportQuery, []string{captureDefault, captureNamespace, captureNamed, captureNamedAlias, capturePath}},
				{"cjsRequire", g.cjsRequireQuery, []string{captureDefault, captureNamed, captureNamedAlias, capturePath}},
				{"directCall", g.directCallQuery, []string{captureFn}},
				{"memberCall", g.memberCallQuery, []string{capturePkg, captureFn, captureSelector}},
				{"directNew", g.directNewQuery, []string{captureClass}},
				{"memberNew", g.memberNewQuery, []string{capturePkg, captureClass, captureSelector}},
				{"inlineRequireCall", g.inlineRequireCallQuery, []string{capturePath, captureFn, captureSelector}},
				{"inlineRequireCallable", g.inlineRequireCallableQuery, []string{capturePath, captureSelector}},
			} {
				require.NotNil(t, tc.query, tc.queryName)

				resolved := make([]string, 0, len(tc.query.captures))
				for captureName := range tc.query.captures {
					resolved = append(resolved, captureName)
				}

				assert.ElementsMatch(t, tc.captures, resolved, "%s capture set", tc.queryName)
			}
		})
	}
}

// Test_newCompiledQuery_UnknownCaptureNameFails covers the loud-failure path: a capture name
// that the query text doesn't define must produce an error rather than silently resolving to
// index 0, which is a valid index and would make the mismatch look like "matched nothing".
func Test_newCompiledQuery_UnknownCaptureNameFails(t *testing.T) {
	t.Parallel()

	language := treesitter.NewLanguage(tree_sitter_javascript.Language())

	// captureFn is defined by this query text; "doesNotExist" is not.
	query, err := newCompiledQuery(language, "test query", tsQueryForDirectCall, captureFn, "doesNotExist")

	require.Error(t, err)
	assert.Nil(t, query)
	assert.Contains(t, err.Error(), `has no capture named "doesNotExist"`)
}

// Test_Detect_JavaScript_NoAdvisories (the fixture-based version, covering the same
// early-return behavior with a real testdata path) lives in detect_test.go.
