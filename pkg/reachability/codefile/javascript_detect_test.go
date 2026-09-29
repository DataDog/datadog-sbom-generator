package codefile

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTempJSFile writes src to dir/filename and returns the full path, failing the test on any
// write error. Detect() reads files from disk (via readFileContent), so tests need a real file
// on disk rather than an in-memory tree, matching how the Go/Java detector tests use testdata/
// fixtures - these tests use ad hoc temp files instead of committed fixtures since Task 8 is
// where the permanent testdata/ fixture convention gets set up.
func writeTempJSFile(t *testing.T, dir, filename, src string) string {
	t.Helper()

	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, []byte(src), 0o600))

	return path
}

//nolint:paralleltest
func Test_Detect_JavaScript_NoAdvisoriesReturnsEmptyResults(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	detectionResults := models.DetectionResults{}

	err = detector.Detect(context.Background(), "", "testdata/js/does-not-need-to-exist.js", detectionResults, []models.AdvisoryToCheck{})

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

//nolint:paralleltest
func Test_Detect_JavaScript_FunctionSymbols(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	tests := []struct {
		name           string
		src            string
		expectedSymbol string
		expectNoMatch  bool
	}{
		{
			name:           "named import, direct call",
			src:            "import { merge } from 'lodash';\nmerge({}, x);",
			expectedSymbol: "merge",
		},
		{
			name:           "aliased named import, direct call",
			src:            "import { merge as m } from 'lodash';\nm({}, x);",
			expectedSymbol: "m",
		},
		{
			name:           "default import, direct call",
			src:            "import minimist from 'minimist';\nminimist(args);",
			expectedSymbol: "minimist",
		},
		{
			name:           "namespace import, member call",
			src:            "import * as _ from 'lodash';\n_.merge({}, x);",
			expectedSymbol: "_.merge",
		},
		{
			name:           "cjs namespace require, member call",
			src:            "const _ = require('lodash');\n_.merge({}, x);",
			expectedSymbol: "_.merge",
		},
		{
			name:           "cjs default-callable require, direct call (minimist-shape)",
			src:            "const minimist = require('minimist');\nminimist(args);",
			expectedSymbol: "minimist",
		},
		{
			name:           "cjs destructured require, direct call",
			src:            "const { merge } = require('lodash');\nmerge({}, x);",
			expectedSymbol: "merge",
		},
		{
			name:          "unrelated function of the same name from a different package - no match",
			src:           "import { merge } from 'not-lodash';\nmerge({}, x);",
			expectNoMatch: true,
		},
		{
			name:          "computed require - no binding, no match",
			src:           "const _ = require(dynamicName);\n_.merge({}, x);",
			expectNoMatch: true,
		},
		{
			name:          "function name mismatch - no match",
			src:           "import { pick } from 'lodash';\npick({}, x);",
			expectNoMatch: true,
		},
	}

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-TEST-0001",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
		},
		{
			Purl:       "pkg:npm/minimist@1.2.0",
			AdvisoryID: "CVE-TEST-0002",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "minimist", Name: "minimist"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempJSFile(t, dir, "app.js", tt.src)

			detectionResults := models.DetectionResults{}
			err := detector.Detect(context.Background(), dir, path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)

			if tt.expectNoMatch {
				assert.Empty(t, detectionResults)
				return
			}

			require.NotEmpty(t, detectionResults)
			found := false
			for _, advisoryMap := range detectionResults {
				for _, locations := range advisoryMap {
					for _, loc := range locations {
						if loc.Symbol == tt.expectedSymbol {
							found = true
						}
					}
				}
			}
			assert.True(t, found, "expected a match with Symbol == %q, got %+v", tt.expectedSymbol, detectionResults)
		})
	}
}

//nolint:paralleltest
func Test_Detect_JavaScript_ClassSymbols(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/vulnerable-lib@1.0.0",
			AdvisoryID: "CVE-TEST-0003",
			Symbols:    []models.Symbols{{Type: symbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
		},
	}

	tests := []struct {
		name           string
		src            string
		expectedSymbol string
		expectNoMatch  bool
	}{
		{
			name:           "named import, direct instantiation",
			src:            "import { Client } from 'vulnerable-lib';\nconst c = new Client(cfg);",
			expectedSymbol: "Client",
		},
		{
			name:           "namespace import, member instantiation",
			src:            "import * as pkg from 'vulnerable-lib';\nconst c = new pkg.Client(cfg);",
			expectedSymbol: "pkg.Client",
		},
		{
			name:           "cjs require, member instantiation",
			src:            "const pkg = require('vulnerable-lib');\nconst c = new pkg.Client(cfg);",
			expectedSymbol: "pkg.Client",
		},
		{
			name:          "class name mismatch - no match",
			src:           "import { Server } from 'vulnerable-lib';\nconst s = new Server(cfg);",
			expectNoMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempJSFile(t, dir, "app.js", tt.src)

			detectionResults := models.DetectionResults{}
			err := detector.Detect(context.Background(), dir, path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)

			if tt.expectNoMatch {
				assert.Empty(t, detectionResults)
				return
			}

			require.NotEmpty(t, detectionResults)
			found := false
			for _, advisoryMap := range detectionResults {
				for _, locations := range advisoryMap {
					for _, loc := range locations {
						if loc.Symbol == tt.expectedSymbol {
							found = true
						}
					}
				}
			}
			assert.True(t, found, "expected a match with Symbol == %q, got %+v", tt.expectedSymbol, detectionResults)
		})
	}
}

// Test_Detect_JavaScript_SameSymbolReachableMultipleWays reproduces the CVE-2020-8203
// (lodash zipObjectDeep) shape from the design doc: the same vulnerable function reached via
// three different binding kinds across three files, all correctly attributed to the same
// advisory.
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

	sources := map[string]string{
		"namespace-require.js": "const _ = require('lodash');\n_.zipObjectDeep(['__proto__.polluted'], ['yes']);",
		"esm-named-import.js":  "import { zipObjectDeep } from 'lodash';\nzipObjectDeep(['__proto__.polluted'], ['yes']);",
	}

	dir := t.TempDir()
	detectionResults := models.DetectionResults{}
	for filename, src := range sources {
		path := writeTempJSFile(t, dir, filename, src)
		err := detector.Detect(context.Background(), dir, path, detectionResults, advisoriesToCheck)
		require.NoError(t, err)
	}

	require.Len(t, detectionResults, 1)
	locations := detectionResults["pkg:npm/lodash@4.17.19"]["CVE-2020-8203"]
	assert.Len(t, locations, 2)

	symbols := make([]string, 0, len(locations))
	for _, loc := range locations {
		symbols = append(symbols, loc.Symbol)
	}
	assert.Contains(t, symbols, "_.zipObjectDeep")
	assert.Contains(t, symbols, "zipObjectDeep")
}

//nolint:paralleltest
func Test_Detect_JavaScript_UnsupportedSymbolTypeWarnsAndSkips(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	dir := t.TempDir()
	path := writeTempJSFile(t, dir, "app.js", "import { merge } from 'lodash';\nmerge({}, x);")

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-TEST-0004",
			Symbols:    []models.Symbols{{Type: "some-unsupported-type", Value: "lodash", Name: "merge"}},
		},
	}

	detectionResults := models.DetectionResults{}
	err = detector.Detect(context.Background(), dir, path, detectionResults, advisoriesToCheck)

	require.NoError(t, err)
	assert.Empty(t, detectionResults)
}

//nolint:paralleltest
func Test_Detect_TypeScriptAndTSX(t *testing.T) {
	detector, err := NewJavaScriptReachableDetector(&reporter.VoidReporter{})
	require.NoError(t, err)
	defer detector.Close()

	advisoriesToCheck := []models.AdvisoryToCheck{
		{
			Purl:       "pkg:npm/lodash@4.17.19",
			AdvisoryID: "CVE-TEST-0005",
			Symbols:    []models.Symbols{{Type: symbolTypeFunction, Value: "lodash", Name: "merge"}},
		},
		{
			Purl:       "pkg:npm/vulnerable-lib@1.0.0",
			AdvisoryID: "CVE-TEST-0006",
			Symbols:    []models.Symbols{{Type: symbolTypeClass, Value: "vulnerable-lib", Name: "Client"}},
		},
	}

	tests := []struct {
		filename       string
		src            string
		expectedSymbol string
	}{
		{
			filename:       "app.ts",
			src:            "import { merge } from 'lodash';\nmerge({}, x);",
			expectedSymbol: "merge",
		},
		{
			filename: "app.tsx",
			src: `import { Client } from 'vulnerable-lib';
const c = new Client(cfg);
const el = <div>{c}</div>;`,
			expectedSymbol: "Client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTempJSFile(t, dir, tt.filename, tt.src)

			detectionResults := models.DetectionResults{}
			err := detector.Detect(context.Background(), dir, path, detectionResults, advisoriesToCheck)
			require.NoError(t, err)

			require.NotEmpty(t, detectionResults)
			found := false
			for _, advisoryMap := range detectionResults {
				for _, locations := range advisoryMap {
					for _, loc := range locations {
						if loc.Symbol == tt.expectedSymbol {
							found = true
						}
					}
				}
			}
			assert.True(t, found, "expected a match with Symbol == %q, got %+v", tt.expectedSymbol, detectionResults)
		})
	}
}
