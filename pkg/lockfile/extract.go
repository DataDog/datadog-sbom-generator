package lockfile

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

var lockfileExtractors = map[string]Extractor{}

// RegisterExtractor registers an extractor for a specific lockfile type.
// This is called by language-specific packages during initialization.
func RegisterExtractor(name models.ParsedFilePath, extractor Extractor) {
	if _, ok := lockfileExtractors[name.String()]; ok {
		panic("an extractor is already registered as " + name.String())
	}

	lockfileExtractors[name.String()] = extractor
}

func FindExtractor(path string, enabledParsers map[string]bool) (Extractor, string) {
	for name, extractor := range lockfileExtractors {
		isEnabled := enabledParsers[name]
		if isEnabled && extractor.ShouldExtract(path) {
			return extractor, name
		}
	}

	return nil, ""
}

func IsSupportedExtractor(lockfile string) bool {
	_, exists := lockfileExtractors[lockfile]
	return exists
}

func ListSupportedExtractors() map[string]Extractor {
	supportedExtractors := make(map[string]Extractor)

	for name, extractor := range lockfileExtractors {
		if extractor.IsOfficiallySupported() {
			supportedExtractors[name] = extractor
		}
	}

	return supportedExtractors
}

func ListNoLockfileExtractorNames() []string {
	var names []string
	for name, extractor := range lockfileExtractors {
		if e, ok := extractor.(NoLockfileExtractor); ok && e.IsNoLockfileParser() {
			names = append(names, name)
		}
	}

	sort.Slice(names, func(i, j int) bool {
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	return names
}

func ListExtractorNames() []string {
	extractors := ListSupportedExtractors()
	extractorNames := make([]string, 0, len(extractors))

	for extractorName := range extractors {
		extractorNames = append(extractorNames, extractorName)
	}

	sort.Slice(extractorNames, func(i, j int) bool {
		return strings.ToLower(extractorNames[i]) < strings.ToLower(extractorNames[j])
	})

	return extractorNames
}

func buildLanguageAndPackageManagerToExtractorsMap() map[string][]string {
	extractors := ListSupportedExtractors()
	indexedMap := make(map[string][]string)

	for extractorName, extractor := range extractors {
		packageManager := extractor.PackageManager()

		// Add mapping by package manager name
		packageManagerKey := strings.ToLower(string(packageManager))
		indexedMap[packageManagerKey] = append(indexedMap[packageManagerKey], extractorName)

		// Add mapping by language name (if package manager has a known language)
		if language, exists := models.PackageManagerToLanguage[packageManager]; exists {
			languageKey := strings.ToLower(string(language))
			indexedMap[languageKey] = append(indexedMap[languageKey], extractorName)
		}
	}

	return indexedMap
}

// ExpandLanguagesAndPackageManagersToExtractors converts a list of language names, package manager names, and extractor names to extractor names only
// If a language name is provided, it expands to all parsers in that language based on known mappings
// If a package manager name is provided, it expands to all parsers for that package manager
// If it's anything else, it's included as-is
func ExpandLanguagesAndPackageManagersToExtractors(parsers []string) []string {
	if len(parsers) == 0 {
		return []string{}
	}

	// Get the language-to-parsers mapping dynamically from registered extractors
	indexedMap := buildLanguageAndPackageManagerToExtractorsMap()

	var expandedParsers []string

	for _, item := range parsers {
		lowerItem := strings.ToLower(item)

		if parsers, exists := indexedMap[lowerItem]; exists {
			// It's a language or package manager, expand to all parsers in that language
			expandedParsers = append(expandedParsers, parsers...)
		} else {
			// We don't know about this parser, pass it through as-is
			expandedParsers = append(expandedParsers, item)
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	var result []string
	for _, parser := range expandedParsers {
		if !seen[parser] {
			seen[parser] = true
			result = append(result, parser)
		}
	}

	// Sort for consistency of result
	sort.Strings(result)

	return result
}

var ErrExtractorNotFound = errors.New("could not determine extractor")

// ScanContext is used to pass context to extractors
// It is passed to extractors to allow them to access the root directory of the scan as well as the reporter
type ScanContext struct {
	EnabledParsers map[string]bool
	RootDir        string
	Reporter       reporter.Reporter
}

func ExtractDeps(f DepFile, context ScanContext) (Lockfile, error) {
	extractor, extractedAs := FindExtractor(f.Path(), context.EnabledParsers)

	if extractor == nil {
		return Lockfile{}, fmt.Errorf("%w for %s", ErrExtractorNotFound, f.Path())
	}

	packages, err := extractor.Extract(f, context)

	if err != nil && extractedAs != "" {
		//nolint:all
		err = fmt.Errorf("(extracting as %s) %w", extractedAs, err)
	}

	// Match extracted packages with source file to enrich their details
	if e, ok := extractor.(ExtractorWithMatcher); ok {
		if matchers := e.GetMatchers(); len(matchers) > 0 {
			for _, matcher := range matchers {
				matchError := matchWithFile(f, packages, matcher, context)
				if matchError != nil {
					// _, _ = fmt.Fprintf(os.Stderr, "there was an error matching the source file %s: %s\n", f.Path(), matchError.Error())
					context.Reporter.Warnf("Failed to match the source file of %s: %s, it leads to incomplete enrichment components\n", f.Path(), matchError.Error())
				}
			}
		}
	}

	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}

		return packages[i].Name < packages[j].Name
	})

	parsedLockfile := Lockfile{
		FilePath: f.Path(),
		ParsedAs: extractedAs,
		Packages: packages,
	}

	depFile, err := OpenLocalDepFile(f.Path())
	if err != nil {
		return parsedLockfile, err
	}
	defer depFile.Close()
	if e, ok := extractor.(ArtifactExtractor); ok {
		artifact, err := e.GetArtifact(depFile, context)
		if err == nil {
			parsedLockfile.Artifact = artifact
		}
	}

	return parsedLockfile, err
}
