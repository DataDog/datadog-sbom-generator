package http

import (
	"fmt"
	"os"
)

const DatadogHeaderAppKey = "dd-application-key"
const DatadogHeaderAPIKey = "dd-api-key"    // #nosec G101
const DatadogHeaderJwtToken = "dd-auth-jwt" // #nosec G101
const HeaderContentType = "Content-Type"
const HeaderContentTypeApplicationJSON = "application/json"

const DatadogHostnameDefault = "api.datadoghq.com"

type DatadogEnvVar string

const (
	DatadogEnvVarSite     DatadogEnvVar = "SITE"
	DatadogEnvVarAPIKey   DatadogEnvVar = "API_KEY"
	DatadogEnvVarAppKey   DatadogEnvVar = "APP_KEY"
	DatadogEnvVarHostname DatadogEnvVar = "HOSTNAME"
	DatadogEnvVarJwtToken DatadogEnvVar = "JWT_TOKEN"
)

// getDatadogEnvVarValue should be used only for Datadog-specific environment variables
// as it checks the given variable with both "DD_" and "DATADOG_" prefixes in that order.
// ex. API_KEY would look for DD_API_KEY then DATADOG_API_KEY
func getDatadogEnvVarValue(variable DatadogEnvVar) (string, bool) {
	prefixes := []string{"DD", "DATADOG"}

	for _, prefix := range prefixes {
		value, ok := getEnvVarValue(fmt.Sprintf("%s_%s", prefix, variable))
		if ok {
			return value, ok
		}
	}

	return "", false
}

// getEnvVarValue returns the value for an environment variable and whether it existed or not.
func getEnvVarValue(variable string) (string, bool) {
	value := os.Getenv(variable)
	return value, value != ""
}

// getDatadogBaseURL returns a base URL to use for Datadog API requests.
// It first checks if a base URL override was given otherwise it builds a URL
// using either the DD_HOSTNAME or the DD_SITE environment variable,
// and finally defaults to the Datadog API hostname.
func getDatadogBaseURL(ddBaseURL string) string {
	if ddBaseURL != "" {
		return ddBaseURL
	}

	prefix := "https://"

	hostname, ok := getDatadogEnvVarValue(DatadogEnvVarHostname)
	if ok {
		return prefix + hostname
	}

	site, ok := getDatadogEnvVarValue(DatadogEnvVarSite)
	if ok {
		return fmt.Sprintf("%sapi.%s", prefix, site)
	}

	return prefix + DatadogHostnameDefault
}

type Header struct {
	Key   string
	Value string
}

// getDatadogAuthHeaders returns the headers needed to make authenticated requests to a Datadog API.
// It first checks if a jwt override was given,
// then checks for the DD_JWT_TOKEN environment variable,
// and finally defaults to the Datadog API and app key environment variables.
func getDatadogAuthHeaders(ddJwtToken string) ([]Header, error) {
	if ddJwtToken != "" {
		return []Header{
			{Key: DatadogHeaderJwtToken, Value: ddJwtToken},
		}, nil
	}

	jwtToken, jwtTokenFound := getDatadogEnvVarValue(DatadogEnvVarJwtToken)
	if jwtTokenFound {
		return []Header{
			{Key: DatadogHeaderJwtToken, Value: jwtToken},
		}, nil
	}

	missingKeys := make([]DatadogEnvVar, 0, 2)

	apiKey, apiKeyFound := getDatadogEnvVarValue(DatadogEnvVarAPIKey)
	if !apiKeyFound {
		missingKeys = append(missingKeys, DatadogEnvVarAPIKey)
	}

	appKey, appKeyFound := getDatadogEnvVarValue(DatadogEnvVarAppKey)
	if !appKeyFound {
		missingKeys = append(missingKeys, DatadogEnvVarAppKey)
	}

	if len(missingKeys) > 0 {
		return nil, fmt.Errorf("missing required Datadog authentication environment variables: %v", missingKeys)
	}

	return []Header{
		{Key: DatadogHeaderAPIKey, Value: apiKey},
		{Key: DatadogHeaderAppKey, Value: appKey},
	}, nil
}
