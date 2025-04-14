package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/DataDog/jsonapi"
)

const resolveSymbolsPath = "api/v2/static-analysis-sca/vulnerabilities/resolve-vulnerable-symbols"

type ResolveVulnerableSymbolsRequest struct {
	ID    string   `json:"id"    jsonapi:"primary,resolve-vulnerable-symbols-request"`
	Purls []string `json:"purls" jsonapi:"attribute"`
}

type ResolveVulnerableSymbolsResponse struct {
	ID      string           `json:"id"      jsonapi:"primary,resolve-vulnerable-symbols-response"`
	Results []SymbolsForPurl `json:"results" jsonapi:"attribute"`
}

type SymbolsForPurl struct {
	Purl              string          `json:"purl"               jsonapi:"attribute"`
	VulnerableSymbols []SymbolDetails `json:"vulnerable_symbols" jsonapi:"attribute"`
}

type SymbolDetails struct {
	AdvisoryID string   `json:"advisory_id" jsonapi:"attribute"`
	Symbols    []Symbol `json:"symbols"     jsonapi:"attribute"`
}

type Symbol struct {
	Type  string `json:"type"  jsonapi:"attribute"`
	Value string `json:"value" jsonapi:"attribute"`
	Name  string `json:"name"  jsonapi:"attribute"`
}

func PostResolveVulnerableSymbols(purls []string, ddBaseURL string, ddJwtToken string) (ResolveVulnerableSymbolsResponse, error) {
	return postResolveVulnerableSymbols(purls, getDatadogBaseURL(ddBaseURL), ddJwtToken)
}

func postResolveVulnerableSymbols(purls []string, baseURL string, ddJwtToken string) (ResolveVulnerableSymbolsResponse, error) {
	data := ResolveVulnerableSymbolsResponse{}

	body, err := jsonapi.Marshal(&ResolveVulnerableSymbolsRequest{
		ID:    "resolve-vulnerable-symbols-request",
		Purls: purls,
	})
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fmt.Sprintf("%s/%s", baseURL, resolveSymbolsPath), bytes.NewBuffer(body))
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to create request: %w", err)
	}

	authHeaders, err := getDatadogAuthHeaders(ddJwtToken)
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] no auth headers retrieved: %w", err)
	}

	req.Header.Set(HeaderContentType, HeaderContentTypeApplicationJSON)
	for _, header := range authHeaders {
		req.Header.Set(header.Key, header.Value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to retrieve vulnerable symbols: %s", resp.Status)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to read response body: %w", err)
	}

	err = jsonapi.Unmarshal(respBytes, &data)
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to unmarshal response: %w", err)
	}

	return data, nil
}
