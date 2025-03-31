package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)
	assert.Len(t, resp.Results, 1)
	assert.Equal(t, resp.Results[0].Purl, "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0")
	assert.Len(t, resp.Results[0].VulnerableSymbols, 2)
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].AdvisoryId, "GHSA-7rjr-3q55-vv33")
	assert.Len(t, resp.Results[0].VulnerableSymbols[0].Symbols, 2)
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[0].Type, "class")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[0].Value, "org.apache.logging.log4j")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[0].Name, "Logger")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[1].Type, "class")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[1].Value, "org.apache.logging.log4j")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[0].Symbols[1].Name, "LogManager")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].AdvisoryId, "GHSA-jfh8-c2jp-5v3q")
	assert.Len(t, resp.Results[0].VulnerableSymbols[1].Symbols, 2)
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[0].Type, "class")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[0].Value, "org.apache.logging.log4j")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[0].Name, "Logger")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[1].Type, "class")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[1].Value, "org.apache.logging.log4j")
	assert.Equal(t, resp.Results[0].VulnerableSymbols[1].Symbols[1].Name, "LogManager")
}

// createMockServer is a thin wrapper used to mock an HTTP server used for testing the status/output of an API request.
// After initializing you must defer the Close action.
func createMockServer(statusCode int, data string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(data))
	}))
}
