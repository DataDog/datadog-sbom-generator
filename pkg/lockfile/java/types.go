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

type MavenInstallFile struct {
	Artifacts map[string]*MavenInstallArtifact `json:"artifacts"`
	// Dependencies is commented out since it isn't currently used.
	// Dependencies map[string][]string `json:"dependencies"`
}

type MavenInstallArtifact struct {
	Version string `json:"version"`
	models.FilePosition
}

type MavenInstallExtractor struct{}

// ============================================================================
// Matcher Types
// ============================================================================

type BuildGradleMatcher struct{}
