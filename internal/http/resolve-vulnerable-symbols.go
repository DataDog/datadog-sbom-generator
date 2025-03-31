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
	ID    string   `jsonapi:"primary,resolve-vulnerable-symbols-request" json:"id"`
	Purls []string `jsonapi:"attribute" json:"purls"`
}

type ResolveVulnerableSymbolsResponse struct {
	ID      string           `jsonapi:"primary,resolve-vulnerable-symbols-response" json:"id"`
	Results []SymbolsForPurl `jsonapi:"attribute" json:"results"`
}

type SymbolsForPurl struct {
	Purl              string          `jsonapi:"attribute" json:"purl"`
	VulnerableSymbols []SymbolDetails `jsonapi:"attribute" json:"vulnerable_symbols"`
}

type SymbolDetails struct {
	AdvisoryId string   `jsonapi:"attribute" json:"advisory_id"`
	Symbols    []Symbol `jsonapi:"attribute" json:"symbols"`
}

type Symbol struct {
	Type  string `jsonapi:"attribute" json:"type"`
	Value string `jsonapi:"attribute" json:"value"`
	Name  string `jsonapi:"attribute" json:"name"`
}

func PostResolveVulnerableSymbols(purls []string) (ResolveVulnerableSymbolsResponse, error) {
	return postResolveVulnerableSymbols(purls, getDatadogHostname())
}

func postResolveVulnerableSymbols(purls []string, baseUrl string) (ResolveVulnerableSymbolsResponse, error) {
	data := ResolveVulnerableSymbolsResponse{}

	body, err := jsonapi.Marshal(&ResolveVulnerableSymbolsRequest{
		ID:    "resolve-vulnerable-symbols-request",
		Purls: purls,
	})
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, fmt.Sprintf("%s/%s", baseUrl, resolveSymbolsPath), bytes.NewBuffer(body))
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] failed to create request: %w", err)
	}

	authHeaders, err := getDatadogAuthHeaders()
	if err != nil {
		return data, fmt.Errorf("[PostResolveVulnerableSymbols] no auth headers retrieved: %w", err)
	}

	req.Header.Set(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_APPLICATION_JSON)
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
