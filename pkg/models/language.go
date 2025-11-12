package models

import (
	"strings"
)

type Language string

// These constants are only used for display purposes.
// For language constants used by our backend, follow this pattern:
// https://github.com/DataDog/datadog-ci/blob/master/src/commands/sbom/types.ts#L1-L10
const (
	Java       Language = "Java"
	Python     Language = "Python"
	Dotnet     Language = ".NET"
	Javascript Language = "Javascript"
	Ruby       Language = "Ruby"
	Go         Language = "Go"
	PHP        Language = "PHP"
	Cpp        Language = "C++"
	Elixir     Language = "Elixir"
	Dart       Language = "Dart"
	R          Language = "R"
	Rust       Language = "Rust"
)

// LanguageGroup represents a grouping of related parsers by their language
type LanguageGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Parsers     []string `json:"parsers"`
}

// ExpandLanguagesToParserNames converts a list of language names and parser names to parser names only
// If a language name is provided, it expands to all parsers in that language based on known mappings
// If it's anything else is provided, it's included as-is
func ExpandLanguagesToParserNames(languagesAndParsers []string) []string {
	if len(languagesAndParsers) == 0 {
		return []string{}
	}

	// Create language-to-parsers mapping based on known file patterns
	languageToParserMap := map[string][]string{
		"java":       {PomXML, GradleLockfile, BuildscriptGradleLockfile, GradleVerificationXML},
		"python":     {RequirementsTXT, PoetryLock, PipfileLock, PdmLock, UvLock},
		"javascript": {PackageLockJSON, YarnLock, PnpmLockYAML},
		"ruby":       {GemfileLock},
		"go":         {GoMod},
		"php":        {ComposerLock},
		"c++":        {ConanLock},
		"rust":       {CargoLock},
		".net":       {PackagesLockJSON},
		"elixir":     {MixLock},
		"dart":       {PubspecLock},
		"r":          {RenvLock},
	}

	var expandedParsers []string

	for _, item := range languagesAndParsers {
		lowerItem := strings.ToLower(item)

		if parsers, exists := languageToParserMap[lowerItem]; exists {
			// It's a language, expand to all parsers in that language
			expandedParsers = append(expandedParsers, parsers...)
		} else {
			// It's not a language, pass it through as-is
			expandedParsers = append(expandedParsers, item)
		}
	}

	// Remove duplicates while preserving order
	seen := make(map[string]bool)
	var result []string
	for _, parser := range expandedParsers {
		if !seen[parser] {
			seen[parser] = true
			result = append(result, parser)
		}
	}

	return result
}
