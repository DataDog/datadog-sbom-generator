package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPackageManagerToLanguage(t *testing.T) {
	t.Parallel()

	expectedMappings := map[PackageManager]Language{
		Maven:        Java,
		Gradle:       Java,
		NPM:          Javascript,
		Yarn:         Javascript,
		Pnpm:         Javascript,
		Requirements: Python,
		Pipfile:      Python,
		Pdm:          Python,
		Poetry:       Python,
		Uv:           Python,
		NuGet:        Dotnet,
		Bundler:      Ruby,
		Golang:       Go,
		Composer:     PHP,
		Crates:       Cpp,
		Conan:        Cpp,
		Hex:          Elixir,
		Pub:          Dart,
		Renv:         R,
	}

	for pm, expectedLang := range expectedMappings {
		t.Run(string(pm), func(t *testing.T) {
			t.Parallel()

			actualLang, exists := PackageManagerToLanguage[pm]
			assert.True(t, exists, "PackageManager %s should exist in the mapping", pm)
			assert.Equal(t, expectedLang, actualLang, "Expected language for %s does not match", pm)
		})
	}
}
