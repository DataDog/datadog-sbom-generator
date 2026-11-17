package codeowners

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type patternTest struct {
	Name    string          `json:"name"`
	Pattern string          `json:"pattern"`
	Paths   map[string]bool `json:"paths"`
	Focus   bool            `json:"focus"`
}

func TestMatch(t *testing.T) {
	data, err := os.ReadFile("testdata/patterns.json")
	require.NoError(t, err)

	var tests []patternTest
	err = json.Unmarshal(data, &tests)
	require.NoError(t, err)

	focus := false
	for _, test := range tests {
		if test.Focus {
			focus = true
		}
	}

	for _, test := range tests {
		if test.Focus != focus {
			continue
		}

		t.Run(test.Name, func(t *testing.T) {
			for path, shouldMatch := range test.Paths {
				pattern, err := newPattern(test.Pattern)
				require.NoError(t, err)

				// Debugging tips:
				// - Print the generated regex: `fmt.Println(pattern.regex.String())`
				// - Only run a single case by adding `"focus" : true` to the test in the JSON file

				actual, err := pattern.match(path)
				require.NoError(t, err)

				if shouldMatch {
					assert.True(t, actual, "expected pattern %s to match path %s", test.Pattern, path)
				} else {
					assert.False(t, actual, "expected pattern %s to not match path %s", test.Pattern, path)
				}
			}
		})
	}
}

func TestRulesetMatchNormalizesWindowsPathSeparators(t *testing.T) {
	ruleset, err := ParseFile(strings.NewReader(`/integration-tests/openfeature/ @DataDog/feature-flagging-and-experimentation-sdk
/* @DataDog/lang-platform-js
`))
	require.NoError(t, err)

	filePath := `integration-tests\openfeature\openfeature-exposure-events.spec.js`

	rootRuleMatches, err := ruleset[1].Match(filePath)
	require.NoError(t, err)
	assert.False(t, rootRuleMatches)

	rule, err := ruleset.Match(filePath)
	require.NoError(t, err)
	require.NotNil(t, rule)
	assert.Equal(t, "/integration-tests/openfeature/", rule.RawPattern())
	assert.Equal(t, []Owner{{Value: "DataDog/feature-flagging-and-experimentation-sdk", Type: TeamOwner}}, rule.Owners)
}
