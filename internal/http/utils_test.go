package http

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getDatadogEnvVarValue_noneSet(t *testing.T) {
	datadogEnvVarsWithoutPrefix := []string{
		"API_KEY",
		"APP_KEY",
		"JWT_TOKEN",
		"SITE",
		"HOSTNAME",
	}

	for _, envVar := range datadogEnvVarsWithoutPrefix {
		t.Run(fmt.Sprintf("%s env var should not be set", envVar), func(t *testing.T) {
			_, found := getDatadogEnvVarValue(envVar)
			assert.False(t, found)
		})
	}
}

func Test_getDatadogEnvVarValue_canReadFromDatadogPrefix(t *testing.T) {
	t.Setenv("DATADOG_API_KEY", "test-datadog-api-key")

	value, found := getDatadogEnvVarValue("API_KEY")
	assert.True(t, found)
	assert.Equal(t, "test-datadog-api-key", value)
}

func Test_getDatadogEnvVarValue_ddPrefixTakesPrecedence(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DATADOG_API_KEY", "test-datadog-api-key")

	value, found := getDatadogEnvVarValue("API_KEY")
	assert.True(t, found)
	assert.Equal(t, "test-dd-api-key", value)
}

func Test_getDatadogHostname_hostnameTakesPrecendence(t *testing.T) {
	t.Setenv("DD_HOSTNAME", "foo.bar.baz")
	t.Setenv("DD_SITE", "datadoghq.eu")

	value := getDatadogHostname()
	assert.Equal(t, "https://foo.bar.baz", value)
}

func Test_getDatadogHostname_usingSiteEnvVar(t *testing.T) {
	t.Setenv("DD_SITE", "datadoghq.eu")

	value := getDatadogHostname()
	assert.Equal(t, "https://api.datadoghq.eu", value)
}

func Test_getDatadogHostname_usingFallback(t *testing.T) {
	value := getDatadogHostname()
	assert.Equal(t, "https://api.datadoghq.com", value)
}

func Test_getDatadogAuthHeaders_noneFoundIsError(t *testing.T) {
	_, err := getDatadogAuthHeaders()
	assert.Error(t, err)
}

func Test_getDatadogAuthHeaders_jwtTokenTakesPrecedence(t *testing.T) {
	t.Setenv("DD_JWT_TOKEN", "test-jwt-token")

	headers, err := getDatadogAuthHeaders()
	assert.NoError(t, err)
	assert.Len(t, headers, 1)
	assert.Equal(t, DATADOG_HEADER_JWT_TOKEN, headers[0].Key)
	assert.Equal(t, "test-jwt-token", headers[0].Value)
}

func Test_getDatadogAuthHeaders_usesApiAndAppKey(t *testing.T) {
	t.Setenv("DD_API_KEY", "test-dd-api-key")
	t.Setenv("DD_APP_KEY", "test-dd-app-key")

	headers, err := getDatadogAuthHeaders()
	assert.NoError(t, err)
	assert.Len(t, headers, 2)
	assert.Equal(t, DATADOG_HEADER_API_KEY, headers[0].Key)
	assert.Equal(t, "test-dd-api-key", headers[0].Value)
	assert.Equal(t, DATADOG_HEADER_APP_KEY, headers[1].Key)
	assert.Equal(t, "test-dd-app-key", headers[1].Value)
}
