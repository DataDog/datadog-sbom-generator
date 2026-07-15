package reachability

import (
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
