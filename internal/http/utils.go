package http

import (
	"fmt"
	"os"
)

const DATADOG_HEADER_APP_KEY = "dd-application-key"
const DATADOG_HEADER_API_KEY = "dd-api-key"
const DATADOG_HEADER_JWT_TOKEN = "dd-auth-jwt"
const HEADER_CONTENT_TYPE = "Content-Type"
const HEADER_CONTENT_TYPE_APPLICATION_JSON = "application/json"

const DATADOG_HOSTNAME_DEFAULT = "api.datadoghq.com"

type DatadogEnvVar string

const (
	DatadogEnvVarSite     DatadogEnvVar = "SITE"
	DatadogEnvVarApiKey                 = "API_KEY"
	DatadogEnvVarAppKey                 = "APP_KEY"
	DatadogEnvVarHostname               = "HOSTNAME"
	DatadogEnvVarJwtToken               = "JWT_TOKEN"
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

	return prefix + DATADOG_HOSTNAME_DEFAULT
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
			{Key: DATADOG_HEADER_JWT_TOKEN, Value: jwtToken},
		}, nil
	}

	missingKeys := make([]string, 0, 2)

	apiKey, apiKeyFound := getDatadogEnvVarValue(DatadogEnvVarApiKey)
	if !apiKeyFound {
		missingKeys = append(missingKeys, DatadogEnvVarApiKey)
	}

	appKey, appKeyFound := getDatadogEnvVarValue(DatadogEnvVarAppKey)
	if !appKeyFound {
		missingKeys = append(missingKeys, DatadogEnvVarAppKey)
	}

	if len(missingKeys) > 0 {
		return nil, fmt.Errorf("missing required Datadog authentication environment variables: %v", missingKeys)
	}

	return []Header{
		{Key: DATADOG_HEADER_API_KEY, Value: apiKey},
		{Key: DATADOG_HEADER_APP_KEY, Value: appKey},
	}, nil

}
