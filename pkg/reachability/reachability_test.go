package reachability

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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

func Test_PerformReachabilityAnalysis(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")
	ddJwtToken := ""

	// Create a mock server to simulate the API response
	// The server will return a successful response with the vulnerable symbols
	mockServer := createMockServer(http.StatusOK, vulnerableSymbolsResponse)
	defer mockServer.Close()

	// Create a temporary directory with a mock Java file
	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	// Create a mock Java file with a vulnerable class (should match the vulnerable symbols)
	mockJavaFile := filepath.Join(tempDir, "subdir", "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	result := PerformReachabilityAnalysis(
		true,
		[]string{},
		[]string{tempDir},
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
	mockServer := createMockServer(http.StatusOK, vulnerableSymbolsResponse)
	defer mockServer.Close()

	// Create a temporary directory with a mock Java file
	tempDir := t.TempDir()
	err := os.Mkdir(filepath.Join(tempDir, "subdir"), 0755)
	require.NoError(t, err)

	// Create a mock Java file with a vulnerable class (should match the vulnerable symbols)
	mockJavaFile := filepath.Join(tempDir, "subdir", "Main.java")
	err = os.WriteFile(mockJavaFile, []byte(vulnerableClass), 0600)
	require.NoError(t, err)

	excludePaths := []string{filepath.Join(tempDir, "subdir", "*")}
	result := PerformReachabilityAnalysis(
		true,
		[]string{},
		[]string{tempDir},
		excludePaths,
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

func createMockServer(statusCode int, data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(data))
	}))
}
