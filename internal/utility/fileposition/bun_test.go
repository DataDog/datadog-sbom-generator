package fileposition

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
)

// joinLines builds a buffer whose 1-indexed line numbers match the slice index
// plus one. Every line's leading whitespace is literal, so the column numbers
// asserted below can be counted directly from each raw-string line.
func joinLines(lines []string) string {
	return strings.Join(lines, "\n") + "\n"
}

func TestInBunLockPackages(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected map[string]models.FilePosition
	}{
		{
			// Mirrors multiple-packages.lock: a single entry, all on one line,
			// indented with 4 spaces so the first non-blank column is 5. The
			// closing "]" sits at column 54, so Column.End is 55.
			name: "single_line",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "lodash": ["lodash@4.17.21", "", {}, "sha512-aaa"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"lodash": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 55},
				},
			},
		},
		{
			// The tuple contains inline nested objects ({ "bin": { "tsc": ... } }).
			// Bracket depth must only return to 0 at the tuple's own closing "]"
			// (column 89), not at either inner "}". Column.End is 90.
			name: "inline_nested_braces",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "typescript": ["typescript@5.3.3", "", { "bin": { "tsc": "bin/tsc" } }, "sha512-bbb"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"typescript": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 90},
				},
			},
		},
		{
			// Scoped key: the map key is preserved verbatim, slashes and all.
			// Closing "]" is at column 89, so Column.End is 90.
			name: "scoped_key",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "@typescript-eslint/types": ["@typescript-eslint/types@5.62.0", "", {}, "sha512-bbb"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"@typescript-eslint/types": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 90},
				},
			},
		},
		{
			// Workspace-style nested key. The input also contains a top-level
			// "workspaces" object with a "packages/a" key, so a scanner that
			// naively substring-matches "packages" would grab the wrong token.
			// Only "packages/a/typescript" (inside the real "packages" object,
			// line 8) must be returned. Closing "]" is at column 71 -> End 72.
			name: "workspace_nested_key",
			input: joinLines([]string{
				`{`,
				`  "workspaces": {`,
				`    "packages/a": {`,
				`      "name": "workspace-a"`,
				`    }`,
				`  },`,
				`  "packages": {`,
				`    "packages/a/typescript": ["typescript@5.3.3", "", {}, "sha512-bbb"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"packages/a/typescript": {
					Line:   models.Position{Start: 8, End: 8},
					Column: models.Position{Start: 5, End: 72},
				},
			},
		},
		{
			// One tuple spans multiple lines: key + "[" on line 3, elements on
			// lines 4-5, closing "]" alone on line 6. Line spans 3..6; the "]"
			// is at column 5 of line 6, so Column.End is 6.
			name: "multiline_synthetic",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "multi": [`,
				`      "multi@1.0.0",`,
				`      {}`,
				`    ]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"multi": {
					Line:   models.Position{Start: 3, End: 6},
					Column: models.Position{Start: 5, End: 6},
				},
			},
		},
		{
			// Highest risk: the spec string contains literal ] } [ { and an
			// escaped quote (\"). The scanner must ignore bracket characters
			// inside the quoted value and must not let the escaped quote end the
			// string. The true closing "]" is at column 61, so Column.End is 62.
			name: "brackets_inside_strings",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "pkg": ["pkg@1.0.0", "note: a]b}c \" [x", {}, "sha512-z"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"pkg": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 62},
				},
			},
		},
		{
			// Mirrors empty-tuple.lock: the tuple is "[]". A delimited position is
			// still returned. "[" at column 15, "]" at column 16 -> End 17.
			name: "empty_tuple",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "broken": []`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"broken": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 17},
				},
			},
		},
		{
			// Mirrors non-string-spec.lock: the first tuple element is a number,
			// not a string. No panic; the position is still returned. Closing "]"
			// is at column 40, so Column.End is 41.
			name: "malformed_non_string_spec",
			input: joinLines([]string{
				`{`,
				`  "packages": {`,
				`    "broken": [42, "", {}, "sha512-aaa"]`,
				`  }`,
				`}`,
			}),
			expected: map[string]models.FilePosition{
				"broken": {
					Line:   models.Position{Start: 3, End: 3},
					Column: models.Position{Start: 5, End: 41},
				},
			},
		},
		{
			// The "packages" object is present but empty: the scanner must return
			// a non-nil, empty map without panicking or hanging.
			name: "empty_packages_object",
			input: joinLines([]string{
				`{`,
				`  "packages": {}`,
				`}`,
			}),
			expected: map[string]models.FilePosition{},
		},
		{
			// The "packages" key is entirely absent: same contract as above, a
			// non-nil, empty map.
			name: "absent_packages_key",
			input: joinLines([]string{
				`{`,
				`  "lockfileVersion": 0,`,
				`  "workspaces": {}`,
				`}`,
			}),
			expected: map[string]models.FilePosition{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := InBunLockPackages([]byte(tt.input))
			assert.Equal(t, tt.expected, got)
		})
	}
}
