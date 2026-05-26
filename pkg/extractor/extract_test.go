package extractor_test

import (
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/internal/output"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	_ "github.com/DataDog/datadog-sbom-generator/pkg/extractor/parsers" // Register all extractors
)

type TestDepFile struct {
	io.Reader

	path string
}

func (f TestDepFile) Open(_ string) (extractor.DepFile, error) {
	return TestDepFile{}, errors.New("file opening is not supported")
}

func (f TestDepFile) Path() string { return f.path }
func (f TestDepFile) Close() error { return nil }

func openTestDepFile(p string) TestDepFile {
	return TestDepFile{strings.NewReader(""), p}
}

var _ extractor.DepFile = TestDepFile{}
var _ extractor.DepFile = TestDepFile{}

func TestFindExtractor(t *testing.T) {
	t.Parallel()

	lockfiles := filesToParsers()
	enabledParsers := make(map[string]bool)
	for file, parserName := range lockfiles {
		enabledParsers[parserName] = true
		extractor, extractedAs := extractor.FindExtractor("/path/to/my/"+file, enabledParsers)

		if extractor == nil {
			t.Errorf("Expected a extractor to be found for %s but did not", file)
		}

		if parserName != extractedAs {
			t.Errorf("Expected extractedAs to be %s but got %s instead", file, extractedAs)
		}
	}
}

func TestExtractDeps_FindsExpectedExtractor(t *testing.T) {
	t.Parallel()

	lockfiles := filesToParsers()
	enabledParsers := make(map[string]bool)
	for _, parserName := range lockfiles {
		enabledParsers[parserName] = true
	}
	delete(enabledParsers, "buildscript-gradle.lockfile") // This extractor does not exist, it uses the gradle one
	count := 0

	for file := range lockfiles {
		context := testutil.GetTestContext()
		context.EnabledParsers = enabledParsers
		_, err := extractor.ExtractDeps(openTestDepFile("/path/to/my/"+file), context)

		if errors.Is(err, extractor.ErrExtractorNotFound) {
			t.Errorf("No extractor was found for %s", file)
		}

		count++
	}

	// gradle.lockfile and buildscript-gradle.lockfile use the same parser
	count -= 1

	expectNumberOfParsersCalled(t, count)
}

func TestExtractDeps_ExtractorNotFound(t *testing.T) {
	t.Parallel()

	_, err := extractor.ExtractDeps(openTestDepFile("/path/to/my/"), testutil.GetTestContext())

	if err == nil {
		t.Errorf("Expected to get an error but did not")
	}

	if !errors.Is(err, extractor.ErrExtractorNotFound) {
		t.Errorf("Did not get the expected ErrExtractorNotFound error - got %v instead", err)
	}
}

func TestExtractDeps_ExtractorNotFound_WithExplicitExtractAs(t *testing.T) {
	t.Parallel()

	_, err := extractor.ExtractDeps(openTestDepFile("/path/to/my/"), testutil.GetTestContext())

	if err == nil {
		t.Errorf("Expected to get an error but did not")
	}

	if !errors.Is(err, extractor.ErrExtractorNotFound) {
		t.Errorf("Did not get the expected ErrExtractorNotFound error - got %v instead", err)
	}
}

func TestListExtractors(t *testing.T) {
	t.Parallel()

	expectedOrder := []string{
		"bun.lock",
		"Cargo.lock",
		"composer.lock",
		"conan.lock",
		"csproj",
		"Gemfile.lock",
		"go.mod",
		"gradle.lockfile",
		"gradle/verification-metadata.xml",
		"maven_install.json",
		"mix.lock",
		"package-lock.json",
		"Package.resolved",
		"packages.lock.json",
		"pdm.lock",
		"Pipfile.lock",
		"pnpm-lock.yaml",
		"poetry.lock",
		"pom.xml",
		"pubspec.lock",
		"requirements.txt",
		"uv.lock",
		"yarn.lock",
	}

	extractors := extractor.ListExtractorNames()

	if len(extractors) != len(expectedOrder) {
		t.Fatalf("Expected %d extractors, but got %d", len(expectedOrder), len(extractors))
	}

	for i, expected := range expectedOrder {
		if extractors[i] != expected {
			t.Errorf("Expected extractors[%d] to be %s, but got %s", i, expected, extractors[i])
		}
	}
}

func TestDisabledExtractor(t *testing.T) {
	t.Parallel()

	extractor, extractedAs := extractor.FindExtractor("/path/to/my/composer.lock", map[string]bool{})

	if extractor != nil {
		t.Errorf("Expected no extractor to be found but one has been found (%s)", extractedAs)
	}
}

func TestIsSupportedExtractor(t *testing.T) {
	t.Parallel()

	// Test with known extractors that should exist
	supportedExtractors := []string{
		"package-lock.json",
		"yarn.lock",
		"pom.xml",
		"go.mod",
		"Gemfile.lock",
		"composer.lock",
	}

	for _, file := range supportedExtractors {
		if !extractor.IsSupportedExtractor(file) {
			t.Errorf("Expected %s to be supported", file)
		}
	}

	// Test with non-existent extractors
	unsupportedExtractors := []string{
		"non-existent.json",
		"fake-extractor.xml",
		"invalid.lock",
		"",
	}

	for _, file := range unsupportedExtractors {
		if extractor.IsSupportedExtractor(file) {
			t.Errorf("Expected %s to not be supported", file)
		}
	}
}

func TestExpandLanguagesAndPackageManagersToExtractors(t *testing.T) {
	t.Parallel()

	// Test empty input
	result := extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{})
	if len(result) != 0 {
		t.Errorf("Expected empty result for empty input, got %v", result)
	}

	// Test language expansion
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"javascript"})
	expected := []string{"bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
	assert.Equal(t, expected, result)

	// Test direct parser name
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"go.mod"})
	expected = []string{"go.mod"}
	assert.Equal(t, expected, result)

	// Test mix of language and parser names
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"go", "package-lock.json"})
	expected = []string{"go.mod", "package-lock.json"}
	assert.Equal(t, expected, result)

	// Test case insensitivity for language names
	result1 := extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"javascript"})
	result2 := extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"JAVASCRIPT"})
	expected = []string{"bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}
	assert.Equal(t, expected, result1)
	assert.Equal(t, expected, result2)

	// Test case expand package manager
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"gradle"})
	expected = []string{"gradle.lockfile", "gradle/verification-metadata.xml"}
	assert.Equal(t, expected, result)

	// Test case expand package manager and language while remove duplicates
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"java", "gradle"})
	expected = []string{"gradle.lockfile", "gradle/verification-metadata.xml", "maven_install.json", "pom.xml"}
	assert.Equal(t, expected, result)

	// Test invalid language/parser names (should be still be passed - validation is not done here)
	result = extractor.ExpandLanguagesAndPackageManagersToExtractors([]string{"invalid-language", "go"})
	expected = []string{"go.mod", "invalid-language"}
	assert.Equal(t, expected, result)
}

func expectNumberOfParsersCalled(t *testing.T, numberOfParsersCalled int) {
	t.Helper()

	// Find all parse-*.go files excluding test files
	files, err := filepath.Glob("*/parse-*.go")
	if err != nil {
		t.Fatalf("unable to glob parse files: %v", err)
	}

	count := 0
	for _, file := range files {
		if !strings.HasSuffix(file, "_test.go") {
			count++
		}
	}

	if numberOfParsersCalled != count {
		t.Errorf(
			"Expected %d %s to have been called, but had %d",
			count,
			output.Form(count, "parser", "parsers"),
			numberOfParsersCalled,
		)
	}
}

func filesToParsers() map[string]string {
	return map[string]string{
		"buildscript-gradle.lockfile":      "gradle.lockfile",
		"bun.lock":                         "bun.lock",
		"Cargo.lock":                       "Cargo.lock",
		"composer.lock":                    "composer.lock",
		"conan.lock":                       "conan.lock",
		"Gemfile.lock":                     "Gemfile.lock",
		"Common.csproj":                    "csproj",
		"go.mod":                           "go.mod",
		"gradle/verification-metadata.xml": "gradle/verification-metadata.xml",
		"gradle.lockfile":                  "gradle.lockfile",
		"library.jar":                      "jar",
		"maven_install.json":               "maven_install.json",
		"mix.lock":                         "mix.lock",
		"pdm.lock":                         "pdm.lock",
		"Pipfile.lock":                     "Pipfile.lock",
		"package.json":                     "package.json",
		"package-lock.json":                "package-lock.json",
		"packages.lock.json":               "packages.lock.json",
		"pnpm-lock.yaml":                   "pnpm-lock.yaml",
		"poetry.lock":                      "poetry.lock",
		"pom.xml":                          "pom.xml",
		"Package.resolved":                 "Package.resolved",
		"pubspec.lock":                     "pubspec.lock",
		"renv.lock":                        "renv.lock",
		"pyproject.toml":                   "pyproject.toml",
		"requirements-example.txt":         "requirements.txt",
		"yarn.lock":                        "yarn.lock",
		"uv.lock":                          "uv.lock",
	}
}
