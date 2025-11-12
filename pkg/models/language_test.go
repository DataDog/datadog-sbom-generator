package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestExpandLanguagesToParserNames(t *testing.T) {
	t.Parallel()

	// Test empty input
	result := models.ExpandLanguagesToParserNames([]string{})
	if len(result) != 0 {
		t.Errorf("Expected empty result for empty input, got %v", result)
	}

	// Test language expansion
	result = models.ExpandLanguagesToParserNames([]string{"javascript"})
	expected := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	assert.Equal(t, expected, result)

	// Test direct parser name
	result = models.ExpandLanguagesToParserNames([]string{"go.mod"})
	expected = []string{"go.mod"}
	assert.Equal(t, expected, result)

	// Test mix of language and parser names
	result = models.ExpandLanguagesToParserNames([]string{"go", "package-lock.json"})
	expected = []string{"go.mod", "package-lock.json"}
	assert.Equal(t, expected, result)

	// Test case insensitivity for language names
	result1 := models.ExpandLanguagesToParserNames([]string{"javascript"})
	result2 := models.ExpandLanguagesToParserNames([]string{"JAVASCRIPT"})
	expected = []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	assert.Equal(t, expected, result1)
	assert.Equal(t, expected, result2)

	// Test invalid language/parser names (should be still be passed - validation is not done here)
	result = models.ExpandLanguagesToParserNames([]string{"invalid-language", "go"})
	expected = []string{"invalid-language", "go.mod"}
	assert.Equal(t, expected, result)
}
