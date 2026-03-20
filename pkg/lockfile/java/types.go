package java

import (
	"encoding/xml"
	"io"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// ============================================================================
// Package Metadata Constants
// ============================================================================

const (
	gradlePackageManager      = models.Gradle
	gradleOfficiallySupported = true

	gradleVerificationPackageManager      = models.Gradle
	gradleVerificationOfficiallySupported = true

	mavenPackageManager      = models.Maven
	mavenOfficiallySupported = true

	mavenInstallPackageManager      = models.Maven
	mavenInstallOfficiallySupported = true
)

// ============================================================================
// File Name Constants
// ============================================================================

const (
	buildGradleFilename    = "build.gradle"
	buildGradleKtsFilename = "build.gradle.kts"
)

// ============================================================================
// Gradle Lock File Constants
// ============================================================================

const (
	gradleLockFileCommentPrefix = "#"
	gradleLockFileEmptyPrefix   = "empty="
)

// ============================================================================
// Gradle Lock Types
// ============================================================================

type GradleLockExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// Gradle Verification Metadata Types
// ============================================================================

type GradleVerificationMetadataFile struct {
	XMLName    xml.Name `xml:"verification-metadata"`
	Components []struct {
		Group   string `xml:"group,attr"`
		Name    string `xml:"name,attr"`
		Version string `xml:"version,attr"`
	} `xml:"components>component"`
}

type GradleVerificationMetadataExtractor struct {
	lockfile.WithMatcher
}

// ============================================================================
// Maven Constants
// ============================================================================

const MavenCentral = "https://repo.maven.apache.org/maven2"

// ============================================================================
// Maven Types
// ============================================================================

type MavenRegistryProject struct {
	io.ReadCloser
	path string
}

type MavenLockDependency struct {
	XMLName    xml.Name                  `xml:"dependency"`
	GroupID    models.StringWithPosition `xml:"groupId"`
	ArtifactID models.StringWithPosition `xml:"artifactId"`
	Version    models.StringWithPosition `xml:"version"`
	Scope      string                    `xml:"scope"`
	Exclusions []MavenLockExclusion      `xml:"exclusions>exclusion"`
	SourceFile string
	models.FilePosition
}

type MavenLockParent struct {
	XMLName      xml.Name `xml:"parent"`
	RelativePath string   `xml:"relativePath"`
	GroupID      string   `xml:"groupId"`
	ArtifactID   string   `xml:"artifactId"`
	Version      string   `xml:"version"`
}

type MavenLockExclusion struct {
	XMLName    xml.Name                  `xml:"exclusion"`
	GroupID    models.StringWithPosition `xml:"groupId"`
	ArtifactID models.StringWithPosition `xml:"artifactId"`
}

type MavenLockDependencyHolder struct {
	Dependencies []MavenLockDependency `xml:"dependency"`
}

type MavenLockFile struct {
	XMLName                  xml.Name                  `xml:"project"`
	Parent                   MavenLockParent           `xml:"parent"`
	Version                  models.StringWithPosition `xml:"version"`
	ModelVersion             models.StringWithPosition `xml:"modelVersion"`
	GroupID                  models.StringWithPosition `xml:"groupId"`
	ArtifactID               models.StringWithPosition `xml:"artifactId"`
	Properties               MavenLockProperties       `xml:"properties"`
	Dependencies             MavenLockDependencyHolder `xml:"dependencies"`
	ManagedDependencies      MavenLockDependencyHolder `xml:"dependencyManagement>dependencies"`
	MainSourceFile           string
	ProjectVersionSourceFile string
}

type MavenLockProperty struct {
	Property   models.StringWithPosition
	SourceFile string
}

type MavenLockProperties struct {
	m map[string]MavenLockProperty
}

type MavenLockExtractor struct {
	lockfile.ArtifactExtractor
}

// ============================================================================
// Maven Install Types
// ============================================================================
//
// maven_install.json is the lockfile for Bazel's rules_jvm_external.
// Two lockfile formats exist:
//
// "Dependency tree" format (rules_jvm_external < 5.1, March 2023):
//   Artifacts under dependency_tree.dependencies[] with "coord" strings.
//   https://github.com/bazel-contrib/rules_jvm_external/blob/master/private/rules/v1_lock_file.bzl
//
// "Artifacts map" format (rules_jvm_external >= 5.1):
//   Artifacts under a top-level "artifacts" map keyed by coordinate.
//   https://github.com/bazel-contrib/rules_jvm_external/blob/master/private/rules/v3_lock_file.bzl

// mavenInstallLockfile represents the "artifacts map" format (rules_jvm_external >= 5.1).
type mavenInstallLockfile struct {
	Artifacts map[string]*mavenInstallArtifact `json:"artifacts"`
}

type mavenInstallArtifact struct {
	Version string `json:"version"`
	models.FilePosition
}

// mavenInstallDepTreeLockfile represents the "dependency tree" format (rules_jvm_external < 5.1).
type mavenInstallDepTreeLockfile struct {
	DependencyTree struct {
		Dependencies []mavenInstallDepTreeArtifact `json:"dependencies"`
	} `json:"dependency_tree"`
}

type mavenInstallDepTreeArtifact struct {
	Coord string `json:"coord"`
}

type MavenInstallExtractor struct{}

// ============================================================================
// Matcher Types
// ============================================================================

type BuildGradleMatcher struct{}
