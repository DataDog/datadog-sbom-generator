package codefile

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	treesitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_resolveImportAliases(t *testing.T) {
	t.Parallel()

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
	}

	for _, tt := range tests {
		t.Run(tt.modulePath, func(t *testing.T) {
			assert.Equal(t, tt.expected, defaultIdentifierForModulePath(tt.modulePath))
		})
	}
}
