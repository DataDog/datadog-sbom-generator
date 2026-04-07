package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/DataDog/jsonapi"
)

const getMergedConfigPath = "api/v2/static-analysis/config/client"
const schemaVersionQueryParam = "schema_version"
const schemaVersion = "v1.1"

type GetMergedConfigRequest struct {
	ID           string  `json:"id"            jsonapi:"primary,config"`
	Repository   string  `json:"repository"    jsonapi:"attribute"`
	ConfigBase64 *string `json:"config_base64" jsonapi:"attribute"`
}

type GetMergedConfigResponse struct {
	ID           string `json:"id"            jsonapi:"primary,config"`
	ConfigBase64 string `json:"config_base64" jsonapi:"attribute"`
}

// PostGetMergedConfig calls the Get Merged endpoint with the repository URL and optional
// local config file contents. It handles base64 encoding/decoding of the config.
// Returns the decoded merged config string.
func PostGetMergedConfig(repoURL string, localConfig *string, ddBaseURL string, ddJwtToken string) (string, error) {
	var configBase64 *string
	if localConfig != nil {
		encoded := base64.StdEncoding.EncodeToString([]byte(*localConfig))
		configBase64 = &encoded
	}

	resp, err := postGetMergedConfig(repoURL, configBase64, getDatadogBaseURL(ddBaseURL), ddJwtToken)
	if err != nil {
		return "", err
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.ConfigBase64)
	if err != nil {
		return "", fmt.Errorf("[PostGetMergedConfig] failed to decode response: %w", err)
	}

	return string(decoded), nil
}

func postGetMergedConfig(repoURL string, configBase64 *string, baseURL string, ddJwtToken string) (GetMergedConfigResponse, error) {
	var data GetMergedConfigResponse

	body, err := jsonapi.Marshal(&GetMergedConfigRequest{
		ID:           "get-merged-config-request",
		Repository:   repoURL,
		ConfigBase64: configBase64,
	})
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fmt.Sprintf("%s/%s", baseURL, getMergedConfigPath), bytes.NewBuffer(body))
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] failed to create request: %w", err)
	}

	q := req.URL.Query()
	q.Set(schemaVersionQueryParam, schemaVersion)
	req.URL.RawQuery = q.Encode()

	authHeaders, err := getDatadogAuthHeaders(ddJwtToken)
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] no auth headers retrieved: %w", err)
	}

	req.Header.Set(HeaderContentType, HeaderContentTypeApplicationJSON)
	for _, header := range authHeaders {
		req.Header.Set(header.Key, header.Value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, fmt.Errorf("[PostGetMergedConfig] failed to retrieve merged config: %s", resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] failed to read response body: %w", err)
	}

	err = jsonapi.Unmarshal(respBytes, &data)
	if err != nil {
		return data, fmt.Errorf("[PostGetMergedConfig] failed to unmarshal response: %w", err)
	}

	return data, nil
}
