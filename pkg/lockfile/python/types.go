package python

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	poetryPackageManager      = models.Poetry
	poetryOfficiallySupported = true

	pipenvPackageManager      = models.Pipfile
	pipenvOfficiallySupported = true

	pdmPackageManager      = models.Pdm
	pdmOfficiallySupported = true

	uvPackageManager      = models.Uv
	uvOfficiallySupported = true

	requirementsPackageManager      = models.Requirements
	requirementsOfficiallySupported = true
)

// ============================================================================
// Requirements.txt Comment Types
// ============================================================================

// CommentType represents the type of dependency comment
type CommentType int

const (
	// CommentTypeNone represents a comment that doesn't have any special meaning,
	// and signifies we're parsing a multiline comment.
	CommentTypeNone CommentType = iota

	// CommentTypeIndirect represents a comment that signifies a package is an
	// indirect dependency.
	CommentTypeIndirect

	// CommentTypeDirect represents a comment that signifies a package is a direct
	// dependency.
	CommentTypeDirect
)

// Comment represents a parsed requirements.txt comment
type Comment struct {
	Content string
	Type    CommentType
}

// CommentParser handles parsing of requirements.txt comments
type CommentParser struct {
	currentComments []*Comment
	multiline       bool
}

// ============================================================================
// Poetry Types
// ============================================================================

type PoetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type PoetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Source   PoetryLockPackageSource `toml:"source"`
}

type PoetryLockFile struct {
	Version  int                  `toml:"version"`
	Packages []*PoetryLockPackage `toml:"package"`
}

type PoetryLockExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// Pipenv Types
// ============================================================================

type PipenvPackage struct {
	Version string `json:"version"`
}

type PipenvLock struct {
	Packages    map[string]PipenvPackage `json:"default"`
	PackagesDev map[string]PipenvPackage `json:"develop"`
}

type PipenvLockExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// PDM Types
// ============================================================================

type PdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type PdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []PdmLockPackage `toml:"package"`
}

type PdmLockExtractor struct{}

// ============================================================================
// UV Types
// ============================================================================

type UvLockPackageSource struct {
	Registry string `toml:"registry,omitempty"`
	Git      string `toml:"git,omitempty"`
	Virtual  string `toml:"virtual,omitempty"`
	Editable string `toml:"editable,omitempty"`
}

type uvDependency struct {
	Name string `toml:"name"`
}

type uvPackageMetadata struct {
	RequiresDist []uvMetadata `toml:"requires-dist"`
}

type uvMetadata struct {
	Name      string `toml:"name"`
	Specifier string `toml:"specifier"`
}

type UvLockPackage struct {
	Name            string                    `toml:"name"`
	Version         string                    `toml:"version"`
	Source          UvLockPackageSource       `toml:"source"`
	Dependencies    []uvDependency            `toml:"dependencies"`
	DevDependencies map[string][]uvDependency `toml:"dev-dependencies"`
}

type UvLockFile struct {
	Version  int               `toml:"version"`
	Packages []*UvLockPackage  `toml:"package"`
	Metadata uvPackageMetadata `toml:"package.metadata"`
}

type UvLockExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// Requirements.txt Types
// ============================================================================

type RequirementsTxtExtractor struct{}

// ============================================================================
// Matcher Types
// ============================================================================

type PipfileMatcher struct{}

type PyprojectTOMLMatcher struct{}
