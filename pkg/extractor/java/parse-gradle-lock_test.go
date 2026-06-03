package java_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGradleLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "buildscript-gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.lockfile/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/buildscript-gradle.extractor.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.buildscript-gradle.lockfile",
			want: false,
		},
		{
			name: "",
			path: "gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/gradle.lockfile",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/gradle.lockfile/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/gradle.extractor.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.gradle.lockfile",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := java.GradleLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGradleLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseGradleLock("../fixtures/gradle-lockfile/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGradleLock_OnlyComments(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseGradleLock("../fixtures/gradle-lockfile/only-comments")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGradleLock_EmptyStatement(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseGradleLock("../fixtures/gradle-lockfile/only-empty")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGradleLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/gradle-lockfile/one-pkg"))
	packages, err := java.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestParseGradleLock_OnePackage_BlockLocation(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/gradle-lockfile/one-pkg"))
	packages, err := java.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	for _, pkg := range packages {
		assert.Positive(t, pkg.BlockLocation.Line.Start,
			"package %s@%s should have BlockLocation.Line.Start > 0", pkg.Name, pkg.Version)
		assert.Positive(t, pkg.BlockLocation.Line.End,
			"package %s@%s should have BlockLocation.Line.End > 0", pkg.Name, pkg.Version)
		assert.Positive(t, pkg.BlockLocation.Column.Start,
			"package %s@%s should have BlockLocation.Column.Start > 0", pkg.Name, pkg.Version)
		assert.Positive(t, pkg.BlockLocation.Column.End,
			"package %s@%s should have BlockLocation.Column.End > 0", pkg.Name, pkg.Version)
		assert.NotEmpty(t, pkg.BlockLocation.Filename,
			"package %s@%s should have BlockLocation.Filename set", pkg.Name, pkg.Version)
	}
}

//nolint:paralleltest
func TestParseGradleLock_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock buildGradleMatcher to fail
	matcherError := errors.New("buildGradleMatcher failed")
	java.GradleExtractor.Matchers = []extractor.Matcher{testutil.FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/gradle-lockfile/one-pkg"))
	packages, err := java.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
	})

	// Reset buildGradleMatcher mock
	testutil.MockAllMatchers()
}

func TestParseGradleLock_MultiplePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/gradle-lockfile/5-pkg"))
	packages, err := java.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-autoconfigure",
			Version:        "2.7.4",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.springframework.boot:spring-boot-configuration-processor",
			Version:        "2.7.5",
			DepGroups:      []string{"annotationProcessor", "compileClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.springframework.boot:spring-boot-devtools",
			Version:        "2.7.6",
			DepGroups:      []string{"developmentOnly", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-aop",
			Version:        "2.7.7",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-data-jpa",
			Version:        "2.7.8",
			DepGroups:      []string{"compileClasspath", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestGradleLockExtractor_GetArtifact(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	tests := []struct {
		name             string
		fixturePath      string
		expectNil        bool
		expectedName     string
		expectedFilename string // just the basename to check
	}{
		{
			name:             "groovy_with_group",
			fixturePath:      "../fixtures/build-gradle/with-group-groovy/gradle.lockfile",
			expectNil:        false,
			expectedName:     "com.example:with-group-groovy",
			expectedFilename: "build.gradle",
		},
		{
			name:             "kotlin_with_group",
			fixturePath:      "../fixtures/build-gradle/with-group-kotlin/gradle.lockfile",
			expectNil:        false,
			expectedName:     "com.example:with-group-kotlin",
			expectedFilename: "build.gradle.kts",
		},
		{
			name:        "no_group",
			fixturePath: "../fixtures/build-gradle/one-package-groovy/gradle.lockfile",
			expectNil:   true,
		},
		{
			name:        "missing_build_file",
			fixturePath: "../fixtures/gradle-lockfile/one-pkg",
			expectNil:   true,
		},
		{
			name:        "group_in_dependency_kwarg_only",
			fixturePath: "../fixtures/build-gradle/one-package-kotlin-extended/gradle.lockfile",
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			absPath := filepath.FromSlash(filepath.Join(dir, tt.fixturePath))
			f, err := extractor.OpenLocalDepFile(absPath)
			if err != nil {
				t.Fatalf("failed to open fixture %s: %v", tt.fixturePath, err)
			}
			defer f.Close()

			ctx := extractor.ScanContext{ExtractMavenPomArtifactIds: true}
			e := java.GradleLockExtractor{}
			artifact, err := e.GetArtifact(f, ctx)

			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, artifact, "expected nil artifact")
			} else if assert.NotNil(t, artifact, "expected non-nil artifact") {
				assert.Equal(t, tt.expectedName, artifact.Name)
				assert.Contains(t, artifact.Filename, tt.expectedFilename)
				assert.Equal(t, models.EcosystemMaven, artifact.Ecosystem)
				assert.Nil(t, artifact.DependsOn)
			}
		})
	}
}

func TestParseGradleLock_WithInvalidLines(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/gradle-lockfile/with-bad-pkg"))
	packages, err := java.ParseGradleLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-autoconfigure",
			Version:        "2.7.4",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.springframework.boot:spring-boot-configuration-processor",
			Version:        "2.7.5",
			DepGroups:      []string{"compileClasspath", "developmentOnly", "productionRuntimeClasspath", "runtimeClasspath"},
			PackageManager: models.Gradle,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}
