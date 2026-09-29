package codefile

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Test_NewJavaScriptReachableDetector_QueriesCompileAndCaptureIndicesResolve smoke-tests that
// every compiled query, for every grammar, actually runs against real parsed source and
// resolves the capture indices this detector relies on. This is a lighter-weight companion to
// the throwaway spike used during development to validate tree-sitter query behavior; it's kept
// here as a regression guard so a future grammar/query change that silently breaks a capture
// name is caught immediately, rather than surfacing later as a resolution/matching bug.
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

			assert.NotNil(t, g.esmImportQuery)
			assert.NotNil(t, g.cjsRequireQuery)
			assert.NotNil(t, g.directCallQuery)
			assert.NotNil(t, g.memberCallQuery)
			assert.NotNil(t, g.directNewQuery)
			assert.NotNil(t, g.memberNewQuery)

			// CaptureIndexForName returns (0, false) for an unresolved name; since 0 is a
			// valid index too, we can't distinguish success from failure by index alone, so
			// instead assert each query's capture actually appears in its own CaptureNames().
			assert.Contains(t, g.esmImportQuery.CaptureNames(), "default")
			assert.Contains(t, g.esmImportQuery.CaptureNames(), "namespace")
			assert.Contains(t, g.esmImportQuery.CaptureNames(), "named")
			assert.Contains(t, g.esmImportQuery.CaptureNames(), "namedAlias")
			assert.Contains(t, g.esmImportQuery.CaptureNames(), "path")

			assert.Contains(t, g.cjsRequireQuery.CaptureNames(), "default")
			assert.Contains(t, g.cjsRequireQuery.CaptureNames(), "named")
			assert.Contains(t, g.cjsRequireQuery.CaptureNames(), "namedAlias")
			assert.Contains(t, g.cjsRequireQuery.CaptureNames(), "path")

			assert.Contains(t, g.directCallQuery.CaptureNames(), "fn")

			assert.Contains(t, g.memberCallQuery.CaptureNames(), "pkg")
			assert.Contains(t, g.memberCallQuery.CaptureNames(), "fn")
			assert.Contains(t, g.memberCallQuery.CaptureNames(), "selector")

			assert.Contains(t, g.directNewQuery.CaptureNames(), "class")

			assert.Contains(t, g.memberNewQuery.CaptureNames(), "pkg")
			assert.Contains(t, g.memberNewQuery.CaptureNames(), "class")
			assert.Contains(t, g.memberNewQuery.CaptureNames(), "selector")
		})
	}
}

// Test_Detect_JavaScript_NoAdvisories (the fixture-based version, covering the same
// early-return behavior with a real testdata path) lives in javascript_detect_test.go.
