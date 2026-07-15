package codefile

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

func Test_NewGoReachableDetector(t *testing.T) {
	t.Parallel()
	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	assert.NotNil(t, detector)
}

func Test_Detect_Go_NoAdvisories(t *testing.T) {
	t.Parallel()
	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := make([]models.AdvisoryToCheck, 0)
	detectionResults := models.DetectionResults{}

	ctx := context.Background()

	err = detector.Detect(ctx, "", "testdata/vulnerable-function.go", detectionResults, advisoriesToCheck)

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

//nolint:paralleltest
func Test_resolveImportAliases(t *testing.T) {
	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	tests := []struct {
		name     string
		src      string
		expected map[string][]string
	}{
		{
			name: "aliased import",
			src: `package main

import bar "github.com/foo/bar"

func main() {
	bar.Parse("x")
}
`,
			expected: map[string][]string{"github.com/foo/bar": {"bar"}},
		},
		{
			name: "unaliased import uses last path segment",
			src: `package main

import "github.com/foo/bar"

func main() {
	bar.Parse("x")
}
`,
			expected: map[string][]string{"github.com/foo/bar": {"bar"}},
		},
		{
			name: "unaliased versioned module path strips major version suffix",
			src: `package main

import "github.com/foo/bar/v2"

func main() {
	bar.Parse("x")
}
`,
			expected: map[string][]string{"github.com/foo/bar/v2": {"bar"}},
		},
		{
			name: "no imports",
			src: `package main

func main() {}
`,
			expected: map[string][]string{},
		},
		{
			name: "blank import is not resolved to a default alias",
			src: `package main

import _ "github.com/foo/bar"

func main() {}
`,
			expected: map[string][]string{},
		},
		{
			name: "dot import is not resolved to a default alias",
			src: `package main

import . "github.com/foo/bar"

func main() {}
`,
			expected: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := detector.tsParser.Parse([]byte(tt.src), nil)
			defer tree.Close()

			queryCursor := treesitter.NewQueryCursor()
			defer queryCursor.Close()

			result := detector.resolveImportAliases(tree, []byte(tt.src), queryCursor)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func Test_defaultIdentifierForModulePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		modulePath string
		expected   string
	}{
		{modulePath: "github.com/foo/bar", expected: "bar"},
		{modulePath: "github.com/foo/bar/v2", expected: "bar"},
		{modulePath: "github.com/foo/bar/v10", expected: "bar"},
		{modulePath: "rsc.io/quote", expected: "quote"},
		{modulePath: "singlesegment", expected: "singlesegment"},
		{modulePath: "gopkg.in/yaml.v3", expected: "yaml"},
		{modulePath: "gopkg.in/check.v1", expected: "check"},
		{modulePath: "github.com/redis/go-redis/v9", expected: "redis"},
		{modulePath: "github.com/mattn/go-sqlite3", expected: "sqlite3"},
		{modulePath: "github.com/CycloneDX/cyclonedx-go", expected: "cyclonedx"},
	}

	for _, tt := range tests {
		t.Run(tt.modulePath, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, defaultIdentifierForModulePath(tt.modulePath))
		})
	}
}

func Test_Detect_Go_FunctionSymbolFound(t *testing.T) {
	t.Parallel()

	fixtures := map[string]struct {
		path              string
		advisoriesToCheck []models.AdvisoryToCheck
	}{
		"aliased import": {
			path: "testdata/CVE-2025-5678/aliased-import/main.go",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/bar", Name: "Parse"},
					},
				},
			},
		},
		"default import": {
			path: "testdata/CVE-2025-5678/default-import/main.go",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/bar", Name: "Parse"},
					},
				},
			},
		},
		"versioned module import": {
			path: "testdata/CVE-2025-5678/versioned-module-path/main.go",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/bar/v2", Name: "Parse"},
					},
				},
			},
		},
		"go- prefixed module import": {
			path: "testdata/CVE-2025-5678/go-prefix-import/main.go",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/go-bar", Name: "Parse"},
					},
				},
			},
		},
		"-go suffixed module import": {
			path: "testdata/CVE-2025-5678/go-suffix-import/main.go",
			advisoriesToCheck: []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/bar-go", Name: "Parse"},
					},
				},
			},
		},
	}

	for name, tc := range fixtures {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
			require.NoError(t, err)
			defer detector.Close()

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", tc.path, detectionResults, tc.advisoriesToCheck)
			require.NoError(t, err)

			advisories, ok := detectionResults["pkg:golang/github.com/foo/bar@1.2.3"]
			require.True(t, ok)
			reachableSymbols, ok := advisories["CVE-2025-5678"]
			require.True(t, ok)
			require.Len(t, reachableSymbols, 1)

			assert.Equal(t, "bar.Parse", reachableSymbols[0].Symbol)
			assert.Equal(t, tc.path, reachableSymbols[0].Filename)
			assert.Equal(t, 6, reachableSymbols[0].LineStart)
			assert.Equal(t, 6, reachableSymbols[0].LineEnd)
			assert.Equal(t, 2, reachableSymbols[0].ColumnStart)
			assert.Equal(t, 11, reachableSymbols[0].ColumnEnd)
		})
	}
}

func Test_Detect_Go_NoMatchWhenFunctionNameDiffers(t *testing.T) {
	t.Parallel()

	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
			AdvisoryID: "CVE-2025-5678",
			Symbols: []models.Symbols{
				{
					Type:  "function",
					Value: "github.com/foo/bar",
					Name:  "SomeOtherFunc",
				},
			},
		},
	}

	detectionResults := models.DetectionResults{}
	err = detector.Detect(context.Background(), ".", "testdata/CVE-2025-5678/aliased-import/main.go", detectionResults, advisoriesToCheck)
	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

func Test_Detect_Go_BlankAndDotImportsNotReachable(t *testing.T) {
	t.Parallel()

	paths := map[string]string{
		"blank import": "testdata/CVE-2025-5678/blank-import/main.go",
		"dot import":   "testdata/CVE-2025-5678/dot-import/main.go",
	}

	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
			require.NoError(t, err)
			defer detector.Close()

			advisoriesToCheck := []models.AdvisoryToCheck{
				{
					Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
					AdvisoryID: "CVE-2025-5678",
					Symbols: []models.Symbols{
						{Type: "function", Value: "github.com/foo/bar", Name: "Parse"},
					},
				},
			}

			detectionResults := models.DetectionResults{}
			err = detector.Detect(context.Background(), ".", path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)
			assert.Empty(t, detectionResults)
		})
	}
}

func Test_Detect_Go_UnknownSymbolType(t *testing.T) {
	t.Parallel()

	detector, err := NewGoReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:golang/github.com/foo/bar@1.2.3",
			AdvisoryID: "CVE-2025-5678",
			Symbols: []models.Symbols{
				{
					Type:  "class",
					Value: "github.com/foo/bar",
					Name:  "Parse",
				},
			},
		},
	}

	detectionResults := models.DetectionResults{}
	err = detector.Detect(context.Background(), ".", "testdata/CVE-2025-5678/aliased-import/main.go", detectionResults, advisoriesToCheck)
	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}
