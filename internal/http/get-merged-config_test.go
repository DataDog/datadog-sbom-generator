package http

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_postGetMergedConfigSuccessful(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusOK, `{
		"data": {
			"id": "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b",
			"type": "config",
			"attributes": {
				"config_base64": "c2NoZW1hLXZlcnNpb246IHYxLjEKc2NhOgogIGlnbm9yZS1wYXRoczoKICAgIC0gdmVuZG9yLyoqCg=="
			}
		}
	}`)
	defer mockServer.Close()

	configBase64 := "c2NoZW1hLXZlcnNpb246IHYxLjEK"
	response, err := postGetMergedConfig("https://github.com/DataDog/example-repo", &configBase64, mockServer.URL, "")
	require.NoError(t, err)
	assert.Equal(t, "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b", response.ID)
	assert.Equal(t, "c2NoZW1hLXZlcnNpb246IHYxLjEKc2NhOgogIGlnbm9yZS1wYXRoczoKICAgIC0gdmVuZG9yLyoqCg==", response.ConfigBase64)
}

func Test_postGetMergedConfigNilConfigBase64(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusOK, `{
		"data": {
			"id": "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b",
			"type": "config",
			"attributes": {
				"config_base64": "c2NoZW1hLXZlcnNpb246IHYxLjEK"
			}
		}
	}`)
	defer mockServer.Close()

	response, err := postGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	require.NoError(t, err)
	assert.NotEmpty(t, response.ConfigBase64)
}

func Test_postGetMergedConfigFailed(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusForbidden, "{}")
	defer mockServer.Close()

	_, err := postGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	assert.Error(t, err)
}

func Test_postGetMergedConfigSetsSchemaVersionQueryParam(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	var capturedQueryParam string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQueryParam = r.URL.Query().Get(schemaVersionQueryParam)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"data": {
				"id": "test",
				"type": "config",
				"attributes": {
					"config_base64": "dGVzdA=="
				}
			}
		}`))
	}))
	defer mockServer.Close()

	_, err := postGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	require.NoError(t, err)
	assert.Equal(t, schemaVersion, capturedQueryParam)
}

func TestPostGetMergedConfigDecodesResponse(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	expectedConfig := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - vendor/**\n"
	encodedConfig := base64.StdEncoding.EncodeToString([]byte(expectedConfig))
	mockServer := createMockServer(http.StatusOK, fmt.Sprintf(`{
		"data": {
			"id": "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b",
			"type": "config",
			"attributes": {
				"config_base64": "%s"
			}
		}
	}`, encodedConfig))
	defer mockServer.Close()

	mergedConfig, err := PostGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	require.NoError(t, err)
	assert.Equal(t, expectedConfig, mergedConfig)
}
