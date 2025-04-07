package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_postResolveVulnerableSymbols_Failed(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusForbidden, "{}")
	defer mockServer.Close()

	_, err := postResolveVulnerableSymbols([]string{}, mockServer.URL)
	assert.Error(t, err)
}

func Test_postResolveVulnerableSymbols_Successful(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusOK, `{
		"data": {
			"id": "833c8b78-f95d-11ef-a104-9ec2f3c6472c",
			"type": "resolve-vulnerable-symbols-response",
			"attributes": {
				"results": [
					{
						"purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0",
						"vulnerable_symbols": [
							{
								"advisory_id": "GHSA-7rjr-3q55-vv33",
								"symbols": [
									{
										"type": "class",
										"value": "org.apache.logging.log4j",
										"name": "Logger"
									},
									{
										"type": "class",
										"value": "org.apache.logging.log4j",
										"name": "LogManager"
									}
								]
							},
							{
								"advisory_id": "GHSA-jfh8-c2jp-5v3q",
								"symbols": [
									{
										"type": "class",
										"value": "org.apache.logging.log4j",
										"name": "Logger"
									},
									{
										"type": "class",
										"value": "org.apache.logging.log4j",
										"name": "LogManager"
									}
								]
							}
						]
					}
				]
			}
		}
	}`)
	defer mockServer.Close()

	resp, err := postResolveVulnerableSymbols([]string{}, mockServer.URL)
	require.NoError(t, err)
	assert.Len(t, resp.Results, 1)
	assert.Equal(t, "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0", resp.Results[0].Purl)
	assert.Len(t, resp.Results[0].VulnerableSymbols, 2)
	assert.Equal(t, "GHSA-7rjr-3q55-vv33", resp.Results[0].VulnerableSymbols[0].AdvisoryID)
	assert.Len(t, resp.Results[0].VulnerableSymbols[0].Symbols, 2)
	assert.Equal(t, "class", resp.Results[0].VulnerableSymbols[0].Symbols[0].Type)
	assert.Equal(t, "org.apache.logging.log4j", resp.Results[0].VulnerableSymbols[0].Symbols[0].Value)
	assert.Equal(t, "Logger", resp.Results[0].VulnerableSymbols[0].Symbols[0].Name)
	assert.Equal(t, "class", resp.Results[0].VulnerableSymbols[0].Symbols[1].Type)
	assert.Equal(t, "org.apache.logging.log4j", resp.Results[0].VulnerableSymbols[0].Symbols[1].Value)
	assert.Equal(t, "LogManager", resp.Results[0].VulnerableSymbols[0].Symbols[1].Name)
	assert.Equal(t, "GHSA-jfh8-c2jp-5v3q", resp.Results[0].VulnerableSymbols[1].AdvisoryID)
	assert.Len(t, resp.Results[0].VulnerableSymbols[1].Symbols, 2)
	assert.Equal(t, "class", resp.Results[0].VulnerableSymbols[1].Symbols[0].Type)
	assert.Equal(t, "org.apache.logging.log4j", resp.Results[0].VulnerableSymbols[1].Symbols[0].Value)
	assert.Equal(t, "Logger", resp.Results[0].VulnerableSymbols[1].Symbols[0].Name)
	assert.Equal(t, "class", resp.Results[0].VulnerableSymbols[1].Symbols[1].Type)
	assert.Equal(t, "org.apache.logging.log4j", resp.Results[0].VulnerableSymbols[1].Symbols[1].Value)
	assert.Equal(t, "LogManager", resp.Results[0].VulnerableSymbols[1].Symbols[1].Name)
}

// createMockServer is a thin wrapper used to mock an HTTP server used for testing the status/output of an API request.
// After initializing you must defer the Close action.
func createMockServer(statusCode int, data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(data))
	}))
}
