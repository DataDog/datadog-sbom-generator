package codefile

import (
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

//nolint:paralleltest
func Test_resolveESMBindings(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	tests := []struct {
		name     string
		src      string
		expected packageBindings
	}{
		{
			name: "default import",
			src:  `import minimist from 'minimist';`,
			expected: packageBindings{
				"minimist": {{localName: "minimist", kind: bindingDefault}},
			},
		},
		{
			name: "namespace import",
			src:  `import * as _ from 'lodash';`,
			expected: packageBindings{
				"lodash": {{localName: "_", kind: bindingNamespace}},
			},
		},
		{
			name: "single named import",
			src:  `import { merge } from 'lodash';`,
			expected: packageBindings{
				"lodash": {{localName: "merge", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name: "aliased named import",
			src:  `import { merge as m } from 'lodash';`,
			expected: packageBindings{
				"lodash": {{localName: "m", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name: "multiple named imports, one aliased",
			src:  `import { merge, pick as p } from 'lodash';`,
			expected: packageBindings{
				"lodash": {
					{localName: "merge", kind: bindingNamed, exportName: "merge"},
					{localName: "p", kind: bindingNamed, exportName: "pick"},
				},
			},
		},
		{
			name: "combined default + namespace",
			src:  `import def, * as ns from 'pkg';`,
			expected: packageBindings{
				"pkg": {
					{localName: "def", kind: bindingDefault},
					{localName: "ns", kind: bindingNamespace},
				},
			},
		},
		{
			name: "combined default + named",
			src:  `import def, { fn } from 'pkg';`,
			expected: packageBindings{
				"pkg": {
					{localName: "def", kind: bindingDefault},
					{localName: "fn", kind: bindingNamed, exportName: "fn"},
				},
			},
		},
		{
			name: "same package imported twice under different local names",
			src: `import * as _ from 'lodash';
import * as lodash2 from 'lodash';`,
			expected: packageBindings{
				"lodash": {
					{localName: "_", kind: bindingNamespace},
					{localName: "lodash2", kind: bindingNamespace},
				},
			},
		},
		{
			name: "multiple different packages",
			src: `import minimist from 'minimist';
import { merge } from 'lodash';`,
			expected: packageBindings{
				"minimist": {{localName: "minimist", kind: bindingDefault}},
				"lodash":   {{localName: "merge", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name:     "no imports",
			src:      `function f() { return 1; }`,
			expected: packageBindings{},
		},
		{
			name:     "side-effect-only import produces no binding",
			src:      `import 'pkg';`,
			expected: packageBindings{
				// side-effect imports (no clause at all) don't match our query since it
				// requires an import_clause; this is intentional - there's no local
				// identifier to resolve a call site against anyway.
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := detector.jsGrammar.parser.Parse([]byte(tt.src), nil)
			defer tree.Close()

			queryCursor := treesitter.NewQueryCursor()
			defer queryCursor.Close()

			result := detector.jsGrammar.resolveESMBindings(tree, []byte(tt.src), queryCursor)

			assert.Equal(t, tt.expected, result)
		})
	}
}

//nolint:paralleltest
func Test_resolveESMBindings_TypeScript(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	tests := []struct {
		name     string
		src      string
		expected packageBindings
	}{
		{
			name: "regular named import in a .ts file",
			src:  `import { merge } from 'lodash';`,
			expected: packageBindings{
				"lodash": {{localName: "merge", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name: "documented gap: import type produces a binding despite having no runtime effect",
			src:  `import type { Merge } from 'lodash';`,
			expected: packageBindings{
				"lodash": {{localName: "Merge", kind: bindingNamed, exportName: "Merge"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := detector.tsGrammar.parser.Parse([]byte(tt.src), nil)
			defer tree.Close()

			queryCursor := treesitter.NewQueryCursor()
			defer queryCursor.Close()

			result := detector.tsGrammar.resolveESMBindings(tree, []byte(tt.src), queryCursor)

			assert.Equal(t, tt.expected, result)
		})
	}
}
