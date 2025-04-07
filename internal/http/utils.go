package http

import (
	"fmt"
	"os"
)

const DatadogHeaderAppKey = "dd-application-key"
const DatadogHeaderApiKey = "dd-api-key"
const DatadogHeaderJwtToken = "dd-auth-jwt"
const HeaderContentType = "Content-Type"
const HeaderContentTypeApplicationJson = "application/json"

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

// getDatadogHostname returns the hostname to use for Datadog API requests. It first checks
// the HOSTNAME environment variable, then the SITE environment variable.
func getDatadogHostname() string {
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

// getDatadogAuthHeaders returns the headers needed to make authenticated requests to a Datadog API. If a JWT token is
// available, it will be used, otherwise the API key and app key will be used.
func getDatadogAuthHeaders() ([]Header, error) {
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
		{Key: DatadogHeaderApiKey, Value: apiKey},
		{Key: DatadogHeaderAppKey, Value: appKey},
	}, nil
}
