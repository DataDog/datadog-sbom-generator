package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_postGetMergedConfig_Successful(t *testing.T) {
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
	resp, err := postGetMergedConfig("https://github.com/DataDog/example-repo", &configBase64, mockServer.URL, "")
	require.NoError(t, err)
	assert.Equal(t, "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b", resp.ID)
	assert.Equal(t, "c2NoZW1hLXZlcnNpb246IHYxLjEKc2NhOgogIGlnbm9yZS1wYXRoczoKICAgIC0gdmVuZG9yLyoqCg==", resp.ConfigBase64)
}

func Test_postGetMergedConfig_NilConfigBase64(t *testing.T) {
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

	resp, err := postGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ConfigBase64)
}

func Test_postGetMergedConfig_Failed(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	mockServer := createMockServer(http.StatusForbidden, "{}")
	defer mockServer.Close()

	_, err := postGetMergedConfig("https://github.com/DataDog/example-repo", nil, mockServer.URL, "")
	assert.Error(t, err)
}

func Test_postGetMergedConfig_SchemaVersionQueryParam(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	var capturedQuery string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedQuery = r.URL.Query().Get("schema_version")
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
	assert.Equal(t, "v1.1", capturedQuery)
}
