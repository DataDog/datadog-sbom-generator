package ruby

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	gemfilePackageManager      = models.Bundler
	gemfileOfficiallySupported = true
)

// ============================================================================
// Gemfile.lock Section Identifiers
// ============================================================================

const (
	lockfileSectionBUNDLED      = "BUNDLED WITH"
	lockfileSectionDEPENDENCIES = "DEPENDENCIES"
	lockfileSectionPLATFORMS    = "PLATFORMS"
	lockfileSectionRUBY         = "RUBY VERSION"
	lockfileSectionGIT          = "GIT"
	lockfileSectionGEM          = "GEM"
	lockfileSectionPATH         = "PATH"
	lockfileSectionPLUGIN       = "PLUGIN SOURCE"
)

// ============================================================================
// File Name Constants
// ============================================================================

const (
	gemfileFilename   = "Gemfile"
	gemspecFileSuffix = ".gemspec"
)

// ============================================================================
// Parser State Enum
// ============================================================================

type parserState string

const (
	parserStateSource      parserState = "source"
	parserStateDependency  parserState = "dependency"
	parserStatePlatform    parserState = "platform"
	parserStateRuby        parserState = "ruby"
	parserStateBundledWith parserState = "bundled_with"
)

// ============================================================================
// Gemfile.lock Parser Types
// ============================================================================

type gemfileLockfileParser struct {
	state          parserState
	dependencies   []lockfile.PackageDetails
	bundlerVersion string
	rubyVersion    string

	// holds the commit of the gem that is currently being parsed, if found
	currentGemCommit string

	// whether or not the parser is in the `DEPENDENCIES` section
	isInDepSection bool
}

type GemfileLockExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// Gemfile Matcher Types
// ============================================================================

type gemMetadata struct {
	name          string
	groups        []string
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

type GemfileMatcher struct{}

// ============================================================================
// Gemspec Matcher Types
// ============================================================================

type gemspecMetadata struct {
	name          string
	isDev         bool
	blockLine     models.Position
	blockColumn   models.Position
	nameLine      models.Position
	nameColumn    models.Position
	versionLine   *models.Position
	versionColumn *models.Position
}

type GemspecFileMatcher struct{}
