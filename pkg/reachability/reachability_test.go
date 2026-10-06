package reachability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"go.uber.org/mock/gomock"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vulnerableSymbolsResponse = `{
	"data": {
		"id": "833c8b78-f95d-11ef-a104-9ec2f3c6472c",
		"type": "resolve-vulnerable-symbols-response",
		"attributes": {
			"results": [
				{
					"purl": "pkg:maven/org.example/Greeter@1.2.3",
					"vulnerable_symbols": [
						{
							"advisory_id": "CVE-2025-1234",
							"symbols": [
								{
									"type": "class",
									"value": "org.example",
									"name": "Greeter"
								}
							]
						}
					]
				}
			]
		}
	}
}`

const vulnerableClass = `
package com.sample;

import org.example.Greeter;

public class ExampleApp {
  public static void main(String[] args) {
    try {
      Greeter greeter = new Greeter("Daniel");
      greeter.sayHello();
    } catch (Exception e ) {
      System.err.println("Greeting failed: " + e.getMessage());
    }
  }
}`

const vulnerableGoSymbolsResponse = `{
	"data": {
		"id": "833c8b78-f95d-11ef-a104-9ec2f3c6472d",
		"type": "resolve-vulnerable-symbols-response",
		"attributes": {
			"results": [
				{
					"purl": "pkg:golang/github.com/foo/bar@1.2.3",
					"vulnerable_symbols": [
						{
							"advisory_id": "CVE-2025-5678",
							"symbols": [
								{
									"type": "function",
									"value": "github.com/foo/bar",
									"name": "Parse"
								}
							]
						}
					]
				}
			]
		}
	}
}`

const vulnerableGoFile = `package main

import bar "github.com/foo/bar"

func main() {
	bar.Parse("x")
}
`

const vulnerableJavaScriptSymbolsResponse = `{
	"data": {
		"id": "833c8b78-f95d-11ef-a104-9ec2f3c6472e",
		"type": "resolve-vulnerable-symbols-response",
		"attributes": {
			"results": [
				{
					"purl": "pkg:npm/lodash@4.17.19",
					"vulnerable_symbols": [
						{
							"advisory_id": "CVE-2025-9012",
							"symbols": [
								{
									"type": "function",
									"value": "lodash",
									"name": "merge"
								}
							]
						}
					]
				}
			]
		}
	}
}`

const vulnerableJavaScriptFile = `import { merge } from 'lodash';
merge({}, x);
`

const vulnerableTypeScriptFile = `import { merge } from 'lodash';
merge({}, x);
`

const vulnerableClassSymbolsResponse = `{
	"data": {
		"id": "833c8b78-f95d-11ef-a104-9ec2f3c6472f",
		"type": "resolve-vulnerable-symbols-response",
		"attributes": {
			"results": [
				{
					"purl": "pkg:npm/vulnerable-lib@1.0.0",
					"vulnerable_symbols": [
						{
							"advisory_id": "CVE-2025-9012",
							"symbols": [
								{
									"type": "class",
									"value": "vulnerable-lib",
									"name": "Client"
								}
							]
						}
					]
				}
			]
		}
	}
}`

// vulnerableTSXFile combines a direct class instantiation with real JSX syntax in the same
// file - proving the full pipeline (directory walk -> extension dispatch -> npm PURL routing ->
// JS detector) correctly reaches a .tsx file specifically, not just the detector in isolation
// (Test_Detect_TypeScriptAndTSX already covers that level).
const vulnerableTSXFile = `import { Client } from 'vulnerable-lib';
const c = new Client(cfg);
const el = <div>{c}</div>;
console.log(el);
`

func Test_PerformReachabilityAnalysis(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	// Create a mock server to simulate the API response
	// The server will return a successful response with the vulnerable symbols
	mockServer := createMockServer(vulnerableSymbolsResponse)
	defer mockServer.Close()

	// Create a temporary directory with a mock Java file
	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	// Create a mock Java file with a vulnerable class (should match the vulnerable symbols)
	mockJavaFile := filepath.Join(tempDir, "subdir", "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	// Expected result
	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:maven/org.example/Greeter@1.2.3": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-1234"},
				ReachableVulnerabilities: []models.ReachableVulnerability{
					{
						AdvisoryID: "CVE-2025-1234",
						ReachableSymbolLocations: []models.ReachableSymbolLocation{
							{
								Symbol: "Greeter",
								PackageLocation: models.PackageLocation{
									Filename:    "subdir/Main.java",
									LineStart:   9,
									LineEnd:     9,
									ColumnStart: 29,
									ColumnEnd:   36,
								},
							},
						},
					},
				},
			},
		},
	}

	// Assert the result
	assert.Equal(t, expected, result)
}

func Test_PerformReachabilityAnalysis_ExcludePath(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	// Create a mock server to simulate the API response
	// The server will return a successful response with the vulnerable symbols
	mockServer := createMockServer(vulnerableSymbolsResponse)
	defer mockServer.Close()

	// Create a temporary directory with a mock Java file
	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	// Create a mock Java file with a vulnerable class (should match the vulnerable symbols)
	mockJavaFile := filepath.Join(tempDir, "subdir", "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	excludePaths := []string{filepath.Join("subdir", "*")}
	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		excludePaths,
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	// Expected result
	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:maven/org.example/Greeter@1.2.3": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked:       []string{"CVE-2025-1234"},
				ReachableVulnerabilities: []models.ReachableVulnerability{}, // should filter out vuln
			},
		},
	}

	// Assert the result
	assert.Equal(t, expected, result)
}

func Test_PerformReachabilityAnalysis_ConfigExcludePath(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	// Create a mock server to simulate the API response
	// The server will return a successful response with the vulnerable symbols
	mockServer := createMockServer(vulnerableSymbolsResponse)
	defer mockServer.Close()

	// Create a temporary directory with a mock Java file
	repoRoot := t.TempDir()
	scanDir := filepath.Join(repoRoot, "subdir")
	err := os.Mkdir(scanDir, 0755)
	require.NoError(t, err)

	// Create a mock Java file with a vulnerable class (should be excluded by config ignore-path)
	mockJavaFile := filepath.Join(scanDir, "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	configExcludePaths := []string{"subdir/**"}
	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{repoRoot},
		[]string{},
		repoRoot,
		configExcludePaths,
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	// Expected result
	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:maven/org.example/Greeter@1.2.3": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked:       []string{"CVE-2025-1234"},
				ReachableVulnerabilities: []models.ReachableVulnerability{}, // should filter out vuln
			},
		},
	}

	// Assert the result
	assert.Equal(t, expected, result)
}

// Test_PerformReachabilityAnalysis_HardcodedExcludedDir covers hardcodedExcludedDirNames: a
// vulnerable file placed directly inside one of these directory names must never be reported,
// regardless of which name it is.
func Test_PerformReachabilityAnalysis_HardcodedExcludedDir(t *testing.T) {
	for dirName := range hardcodedExcludedDirNames {
		t.Run(dirName, func(t *testing.T) {
			t.Setenv("DD_API_KEY", "test-dd-api-key")
			t.Setenv("DD_APP_KEY", "test-dd-app-key")
			ddJwtToken := ""

			mockServer := createMockServer(vulnerableSymbolsResponse)
			defer mockServer.Close()

			tempDir := t.TempDir()
			excludedSubdir := filepath.Join(tempDir, dirName)
			err := os.Mkdir(excludedSubdir, 0755)
			require.NoError(t, err)

			mockJavaFile := filepath.Join(excludedSubdir, "Main.java")
			err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
			require.NoError(t, err)

			mockReporter := createMockReporter(t)

			result := PerformReachabilityAnalysis(
				mockReporter,
				[]string{},
				[]string{tempDir},
				[]string{},
				"",
				[]string{},
				mockServer.URL,
				ddJwtToken,
				true, true,
			)

			expected := models.ReachabilityAnalysis{
				PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
					"pkg:maven/org.example/Greeter@1.2.3": &models.ReachabilityAnalysisResults{
						AdvisoryIdsChecked:       []string{"CVE-2025-1234"},
						ReachableVulnerabilities: []models.ReachableVulnerability{}, // should filter out vuln
					},
				},
			}

			assert.Equal(t, expected, result)
		})
	}
}

// Test_PerformReachabilityAnalysis_HardcodedExcludedDirIsUnconditional proves the exclusion
// applies even with useGitIgnore=false, i.e. it isn't just incidentally passing because every
// other test happens to pass useGitIgnore=true. --no-ignore only disables .gitignore-file-based
// exclusion; hardcodedExcludedDirNames pruning is independent of it.
func Test_PerformReachabilityAnalysis_HardcodedExcludedDirIsUnconditional(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	mockServer := createMockServer(vulnerableSymbolsResponse)
	defer mockServer.Close()

	tempDir := t.TempDir()
	excludedSubdir := filepath.Join(tempDir, "node_modules")
	err := os.Mkdir(excludedSubdir, 0755)
	require.NoError(t, err)

	mockJavaFile := filepath.Join(excludedSubdir, "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		false, false, // useGitIgnore=false: only .gitignore-based exclusion is disabled
	)

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:maven/org.example/Greeter@1.2.3": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked:       []string{"CVE-2025-1234"},
				ReachableVulnerabilities: []models.ReachableVulnerability{}, // should filter out vuln
			},
		},
	}

	assert.Equal(t, expected, result)
}

func Test_PerformReachabilityAnalysis_Go(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	mockServer := createMockServer(vulnerableGoSymbolsResponse)
	defer mockServer.Close()

	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	mockGoFile := filepath.Join(tempDir, "subdir", "main.go")
	err = os.WriteFile(mockGoFile, []byte(vulnerableGoFile), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:golang/github.com/foo/bar@1.2.3": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-5678"},
				ReachableVulnerabilities: []models.ReachableVulnerability{
					{
						AdvisoryID: "CVE-2025-5678",
						ReachableSymbolLocations: []models.ReachableSymbolLocation{
							{
								Symbol: "bar.Parse",
								PackageLocation: models.PackageLocation{
									Filename:    "subdir/main.go",
									LineStart:   6,
									LineEnd:     6,
									ColumnStart: 2,
									ColumnEnd:   11,
								},
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expected, result)
}

func Test_PerformReachabilityAnalysis_JavaScript(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	mockServer := createMockServer(vulnerableJavaScriptSymbolsResponse)
	defer mockServer.Close()

	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	mockJSFile := filepath.Join(tempDir, "subdir", "main.js")
	err = os.WriteFile(mockJSFile, []byte(vulnerableJavaScriptFile), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:npm/lodash@4.17.19": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-9012"},
				ReachableVulnerabilities: []models.ReachableVulnerability{
					{
						AdvisoryID: "CVE-2025-9012",
						ReachableSymbolLocations: []models.ReachableSymbolLocation{
							{
								Symbol: "merge",
								PackageLocation: models.PackageLocation{
									Filename:    "subdir/main.js",
									LineStart:   2,
									LineEnd:     2,
									ColumnStart: 1,
									ColumnEnd:   6,
								},
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expected, result)
}

// Test_PerformReachabilityAnalysis_TypeScript confirms the same npm PURL routing and
// extensionToLanguageKey dispatch also work for a .ts file - the whole point of routing every
// JS/TS/JSX/TSX extension to one shared "javascript" language key is that this requires no
// separate wiring per extension.
func Test_PerformReachabilityAnalysis_TypeScript(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	mockServer := createMockServer(vulnerableJavaScriptSymbolsResponse)
	defer mockServer.Close()

	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	mockTSFile := filepath.Join(tempDir, "subdir", "main.ts")
	err = os.WriteFile(mockTSFile, []byte(vulnerableTypeScriptFile), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:npm/lodash@4.17.19": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-9012"},
				ReachableVulnerabilities: []models.ReachableVulnerability{
					{
						AdvisoryID: "CVE-2025-9012",
						ReachableSymbolLocations: []models.ReachableSymbolLocation{
							{
								Symbol: "merge",
								PackageLocation: models.PackageLocation{
									Filename:    "subdir/main.ts",
									LineStart:   2,
									LineEnd:     2,
									ColumnStart: 1,
									ColumnEnd:   6,
								},
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expected, result)
}

// Test_PerformReachabilityAnalysis_TSX confirms the full pipeline reaches a .tsx file
// specifically, combining a class instantiation with real JSX syntax in the same file - closing
// the gap where only Test_Detect_TypeScriptAndTSX (detector-level) previously covered .tsx, with
// nothing proving the directory-walk/PURL-routing layers above it also reach a .tsx file.
func Test_PerformReachabilityAnalysis_TSX(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	mockServer := createMockServer(vulnerableClassSymbolsResponse)
	defer mockServer.Close()

	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	mockTSXFile := filepath.Join(tempDir, "subdir", "main.tsx")
	err = os.WriteFile(mockTSXFile, []byte(vulnerableTSXFile), 0600)
	require.NoError(t, err)

	mockReporter := createMockReporter(t)

	result := PerformReachabilityAnalysis(
		mockReporter,
		[]string{},
		[]string{tempDir},
		[]string{},
		"",
		[]string{},
		mockServer.URL,
		ddJwtToken,
		true, true,
	)

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:npm/vulnerable-lib@1.0.0": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-9012"},
				ReachableVulnerabilities: []models.ReachableVulnerability{
					{
						AdvisoryID: "CVE-2025-9012",
						ReachableSymbolLocations: []models.ReachableSymbolLocation{
							{
								Symbol: "Client",
								PackageLocation: models.PackageLocation{
									Filename:    "subdir/main.tsx",
									LineStart:   2,
									LineEnd:     2,
									ColumnStart: 15,
									ColumnEnd:   21,
								},
							},
						},
					},
				},
			},
		},
	}

	assert.Equal(t, expected, result)
}

// Test_PerformReachabilityAnalysis_KeepsFirstLocationInWalkOrder: when many files reach the same
// advisory, only the first file in walk order (across directoryPaths) is reported, on every run.
// a.js's match is on a later line than every other file's, so "earliest line" would pick a
// different file than "first in walk order".
func Test_PerformReachabilityAnalysis_KeepsFirstLocationInWalkOrder(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(vulnerableJavaScriptSymbolsResponse)
	defer mockServer.Close()

	firstDir := t.TempDir()
	secondDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(firstDir, "a.js"), []byte("import { merge } from 'lodash';\n\n\nmerge({}, x);\nmerge({}, y);\n"), 0600))
	for i := 1; i < 30; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(firstDir, fmt.Sprintf("b%02d.js", i)), []byte(vulnerableJavaScriptFile), 0600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(secondDir, "a.js"), []byte(vulnerableJavaScriptFile), 0600))

	expected := models.ReachabilityAnalysis{
		PurlToReachabilityAnalysisResults: models.PurlToReachabilityAnalysisResults{
			"pkg:npm/lodash@4.17.19": &models.ReachabilityAnalysisResults{
				AdvisoryIdsChecked: []string{"CVE-2025-9012"},
				ReachableVulnerabilities: []models.ReachableVulnerability{{
					AdvisoryID: "CVE-2025-9012",
					ReachableSymbolLocations: []models.ReachableSymbolLocation{{
						Symbol: "merge",
						PackageLocation: models.PackageLocation{
							Filename: "a.js", LineStart: 4, LineEnd: 4, ColumnStart: 1, ColumnEnd: 6,
						},
					}},
				}},
			},
		},
	}

	for range 3 {
		result := PerformReachabilityAnalysis(
			createMockReporter(t), []string{}, []string{firstDir, secondDir}, []string{}, "", []string{},
			mockServer.URL, "", true, true,
		)
		assert.Equal(t, expected, result)
	}
}

func createMockServer(data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data))
	}))
}

func createMockReporter(t *testing.T) *reporter.MockReporter {
	t.Helper() // Mark this function as a test helper

	// Mock reporter
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()
	mockReporter.EXPECT().Errorf(gomock.Any(), gomock.Any()).AnyTimes()

	return mockReporter
}
