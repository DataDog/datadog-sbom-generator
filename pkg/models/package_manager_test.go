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
		Crates:       Rust,
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

func TestFilePaths(t *testing.T) {
	t.Parallel()

	expectedFilePaths := map[string]string{
		"NpmFilePath":               "package-lock.json",
		"YarnFilePath":              "yarn.lock",
		"PnpmFilePath":              "pnpm-lock.yaml",
		"RequirementsFilePath":      "requirements.txt",
		"PipfileFilePath":           "Pipfile.lock",
		"PdmFilePath":               "pdm.lock",
		"PoetryFilePath":            "poetry.lock",
		"UvFilePath":                "uv.lock",
		"NugetLockFilePath":         "packages.lock.json",
		"BundlerFilePath":           "Gemfile.lock",
		"GolangFilePath":            "go.mod",
		"ComposerFilePath":          "composer.lock",
		"MavenFilePath":             "pom.xml",
		"CratesFilePath":            "Cargo.lock",
		"GradleFilePath":            "gradle.lockfile",
		"GradleBuildScriptFilePath": "buildscript-gradle.lockfile",
		"ConanFilePath":             "conan.lock",
		"HexFilePath":               "mix.lock",
		"PubFilePath":               "pubspec.lock",
		"RenvFilePath":              "renv.lock",
		"ApkFilePath":               "/lib/apk/db/installed",
		"DpkgFilePath":              "/var/lib/dpkg/status",
	}

	actualFilePaths := map[string]ParsedFilePath{
		"NpmFilePath":               NpmFilePath,
		"YarnFilePath":              YarnFilePath,
		"PnpmFilePath":              PnpmFilePath,
		"RequirementsFilePath":      RequirementsFilePath,
		"PipfileFilePath":           PipfileFilePath,
		"PdmFilePath":               PdmFilePath,
		"PoetryFilePath":            PoetryFilePath,
		"UvFilePath":                UvFilePath,
		"NugetLockFilePath":         NugetLockFilePath,
		"BundlerFilePath":           BundlerFilePath,
		"GolangFilePath":            GolangFilePath,
		"ComposerFilePath":          ComposerFilePath,
		"MavenFilePath":             MavenFilePath,
		"CratesFilePath":            CratesFilePath,
		"GradleFilePath":            GradleFilePath,
		"GradleBuildScriptFilePath": GradleBuildScriptFilePath,
		"ConanFilePath":             ConanFilePath,
		"HexFilePath":               HexFilePath,
		"PubFilePath":               PubFilePath,
		"RenvFilePath":              RenvFilePath,
		"ApkFilePath":               ApkFilePath,
		"DpkgFilePath":              DpkgFilePath,
	}

	for key, expected := range expectedFilePaths {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			actual, exists := actualFilePaths[key]
			assert.True(t, exists, "Key %s should exist", key)
			assert.Equal(t, expected, actual, "Value for %s does not match", key)
		})
	}
}
