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

//nolint:paralleltest
func Test_resolveCJSBindings(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	tests := []struct {
		name     string
		src      string
		expected packageBindings
	}{
		{
			name: "plain identifier require produces both Namespace and Default bindings",
			src:  `const _ = require('lodash');`,
			expected: packageBindings{
				"lodash": {
					{localName: "_", kind: bindingNamespace},
					{localName: "_", kind: bindingDefault},
				},
			},
		},
		{
			name: "destructured require, single property",
			src:  `const { merge } = require('lodash');`,
			expected: packageBindings{
				"lodash": {{localName: "merge", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name: "destructured require, aliased property",
			src:  `const { merge: m } = require('lodash');`,
			expected: packageBindings{
				"lodash": {{localName: "m", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name: "destructured require, multiple properties, one aliased",
			src:  `const { merge, pick: p } = require('lodash');`,
			expected: packageBindings{
				"lodash": {
					{localName: "merge", kind: bindingNamed, exportName: "merge"},
					{localName: "p", kind: bindingNamed, exportName: "pick"},
				},
			},
		},
		{
			name: "let and var work the same as const",
			src: `let a = require('pkg-a');
var b = require('pkg-b');`,
			expected: packageBindings{
				"pkg-a": {
					{localName: "a", kind: bindingNamespace},
					{localName: "a", kind: bindingDefault},
				},
				"pkg-b": {
					{localName: "b", kind: bindingNamespace},
					{localName: "b", kind: bindingDefault},
				},
			},
		},
		{
			name: "same package required twice under different local names",
			src: `const _ = require('lodash');
const lodash2 = require('lodash');`,
			expected: packageBindings{
				"lodash": {
					{localName: "_", kind: bindingNamespace},
					{localName: "_", kind: bindingDefault},
					{localName: "lodash2", kind: bindingNamespace},
					{localName: "lodash2", kind: bindingDefault},
				},
			},
		},
		{
			name:     "computed require produces no binding",
			src:      `const bad = require(dynamicName);`,
			expected: packageBindings{
				// intentionally empty: require(variable) doesn't match cjsRequireQuery at all.
			},
		},
		{
			name:     "template-string require, no interpolation, produces no binding",
			src:      "const bad = require(`lodash`);",
			expected: packageBindings{
				// intentionally empty: any template_string argument is out of scope,
				// regardless of whether it contains an interpolation.
			},
		},
		{
			name:     "template-string require with interpolation produces no binding",
			src:      "const bad = require(`./drivers/${name}`);",
			expected: packageBindings{
				// intentionally empty: same as above.
			},
		},
		{
			// require(id) only ever resolves its first argument - a second string must not
			// shadow it. Before the leading-only anchor, this either matched both strings or
			// neither; now it correctly binds just "otherName", the one Node actually loads.
			name: "require call with a second string argument binds only the first argument",
			src:  `const lib = require('otherName', 'lodash');`,
			expected: packageBindings{
				"otherName": {
					{localName: "lib", kind: bindingNamespace},
					{localName: "lib", kind: bindingDefault},
				},
			},
		},
		{
			// The false-positive case this whole fix targets: a variable first argument (the
			// real, unresolvable target) with a decoy string second - must produce no binding
			// at all, since the string genuinely isn't the first argument.
			name:     "require call with a variable first argument and a decoy string second argument produces no binding",
			src:      `const lib = require(otherName, "lodash");`,
			expected: packageBindings{
				// intentionally empty: the string isn't the first argument, so it must not be
				// treated as a module specifier.
			},
		},
		{
			// A real, legitimately-resolvable require with a harmless extra argument after it
			// must still be caught - missing this would be a worse outcome for a vulnerability
			// scanner than the rare false positive the old two-sided anchor was avoiding.
			name: "destructured require with an extra argument still binds the first argument",
			src:  `const { merge } = require('lodash', extra);`,
			expected: packageBindings{
				"lodash": {{localName: "merge", kind: bindingNamed, exportName: "merge"}},
			},
		},
		{
			name:     "not a require call produces no binding",
			src:      `const x = someOtherFunction('pkg');`,
			expected: packageBindings{
				// intentionally empty: function name must be exactly "require".
			},
		},
		{
			name:     "no requires",
			src:      `function f() { return 1; }`,
			expected: packageBindings{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := detector.jsGrammar.parser.Parse([]byte(tt.src), nil)
			defer tree.Close()

			queryCursor := treesitter.NewQueryCursor()
			defer queryCursor.Close()

			bindings := make(packageBindings)
			detector.jsGrammar.resolveCJSBindings(tree, []byte(tt.src), queryCursor, bindings)

			assert.Equal(t, tt.expected, bindings)
		})
	}
}

// Test_resolveCJSBindings_MergesWithExistingESMBindings verifies that CJS bindings are appended
// alongside any pre-existing ESM bindings for the same package (the real usage pattern in
// Detect(): resolveESMBindings runs first into a fresh map, then resolveCJSBindings merges into
// that same map), rather than overwriting them.
//
//nolint:paralleltest
func Test_resolveCJSBindings_MergesWithExistingESMBindings(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	esmSrc := `import { merge } from 'lodash';`
	cjsSrc := `const _ = require('lodash');`

	esmTree := detector.jsGrammar.parser.Parse([]byte(esmSrc), nil)
	defer esmTree.Close()
	esmCursor := treesitter.NewQueryCursor()
	defer esmCursor.Close()
	bindings := detector.jsGrammar.resolveESMBindings(esmTree, []byte(esmSrc), esmCursor)

	cjsTree := detector.jsGrammar.parser.Parse([]byte(cjsSrc), nil)
	defer cjsTree.Close()
	cjsCursor := treesitter.NewQueryCursor()
	defer cjsCursor.Close()
	detector.jsGrammar.resolveCJSBindings(cjsTree, []byte(cjsSrc), cjsCursor, bindings)

	assert.Equal(t, packageBindings{
		"lodash": {
			{localName: "merge", kind: bindingNamed, exportName: "merge"},
			{localName: "_", kind: bindingNamespace},
			{localName: "_", kind: bindingDefault},
		},
	}, bindings)
}
