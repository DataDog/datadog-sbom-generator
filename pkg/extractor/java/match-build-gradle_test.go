package java_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

var buildGradleMatcher = java.BuildGradleMatcher{}

func TestBuildGradleMatcher_GetSourceFile_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	lockFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/does-not-exist/gradle.lockfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := buildGradleMatcher.GetSourceFile(lockFile)
	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	assert.Equal(t, "", sourceFile.Path())
}

func TestBuilGradleMatcher_GetSourceFile_Lockfile_Groovy(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/build-gradle/one-package-groovy/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"build.gradle"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "gradle.lockfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := buildGradleMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestBuilGradleMatcher_GetSourceFile_VerificationMetadata_Groovy(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/build-gradle/one-package-groovy/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"build.gradle"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "/gradle/verification-metadata.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := buildGradleMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestBuilGradleMatcher_GetSourceFile_Lockfile_Kotlin(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/build-gradle/one-package-kotlin/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"build.gradle.kts"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "gradle.lockfile")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := buildGradleMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestBuilGradleMatcher_GetSourceFile_VerificationMetadata_Kotlin(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	basePath := "../fixtures/build-gradle/one-package-kotlin/"
	sourcefilePath := filepath.FromSlash(filepath.Join(dir, basePath+"build.gradle.kts"))

	lockFile, err := extractor.OpenLocalDepFile(basePath + "/gradle/verification-metadata.xml")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := buildGradleMatcher.GetSourceFile(lockFile)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	assert.Equal(t, sourcefilePath, sourceFile.Path())
}

func TestBuildGradleMatcher_Match_OnePackage_Groovy(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/one-package-groovy/build.gradle")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
		},
	}
	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexepcted error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 77},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 48, End: 70},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 71, End: 76},
				Filename: sourceFile.Path(),
			},
		},
	})
}

func TestBuildGradleMatcher_Match_OnePackage_GroovyExtended(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/one-package-groovy-extended/build.gradle")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
		},
	}
	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexepcted error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 105},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 64, End: 86},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 99, End: 104},
				Filename: sourceFile.Path(),
			},
		},
	})
}

func TestBuildGradleMatcher_Match_OnePackage_Kotlin(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/one-package-kotlin/build.gradle.kts")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
		},
	}
	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexepcted error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 78},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 48, End: 70},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 71, End: 76},
				Filename: sourceFile.Path(),
			},
		},
	})
}

func TestBuildGradleMatcher_Match_OnePackage_KotlinExtended(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/one-package-kotlin-extended/build.gradle.kts")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
		},
	}
	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexepcted error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 109},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 66, End: 88},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 102, End: 107},
				Filename: sourceFile.Path(),
			},
		},
	})
}

func TestBuildGradleMatcher_Match_OneRuntimePackage_Kotlin(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/one-package-runtime/build.gradle.kts")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			DepGroups:      []string{"testRuntimeClasspath"},
		},
	}
	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			DepGroups:      []string{"testRuntimeClasspath", "runtimeClasspath"},
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 75},
				Filename: sourceFile.Path(),
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 45, End: 67},
				Filename: sourceFile.Path(),
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 68, End: 73},
				Filename: sourceFile.Path(),
			},
		},
	})
}

func TestBuildGradleMatcher_Match_MultiModule(t *testing.T) {
	t.Parallel()

	sourceFile, err := extractor.OpenLocalDepFile("../fixtures/build-gradle/multi-module/build.gradle")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	packages := []extractor.PackageDetails{
		{
			Name:           "com.google.guava:guava",
			Version:        "32.0.0-jre",
			PackageManager: models.Gradle,
		},
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
		},
		{
			Name:           "com.fasterxml.jackson.core:jackson-databind",
			Version:        "2.15.0",
			PackageManager: models.Gradle,
		},
		{
			Name:           "com.fasterxml.jackson.core:jackson-core",
			Version:        "2.15.0",
			PackageManager: models.Gradle,
		},
	}

	err = buildGradleMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.guava:guava",
			Version:        "32.0.0-jre",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 53},
				Filename: packages[0].BlockLocation.Filename,
			},
			LocationRole:    models.LocationRoleManifest,
			NameLocation:    packages[0].NameLocation,
			VersionLocation: packages[0].VersionLocation,
		},
		{
			Name:           "org.springframework.security:spring-security-crypto",
			Version:        "5.7.3",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 66},
				Filename: packages[1].BlockLocation.Filename,
			},
			LocationRole:    models.LocationRoleManifest,
			NameLocation:    packages[1].NameLocation,
			VersionLocation: packages[1].VersionLocation,
		},
		{
			Name:           "com.fasterxml.jackson.core:jackson-databind",
			Version:        "2.15.0",
			PackageManager: models.Gradle,
			IsDirect:       true,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 3, End: 70},
				Filename: packages[2].BlockLocation.Filename,
			},
			LocationRole:    models.LocationRoleManifest,
			NameLocation:    packages[2].NameLocation,
			VersionLocation: packages[2].VersionLocation,
		},
		{
			Name:           "com.fasterxml.jackson.core:jackson-core",
			Version:        "2.15.0",
			PackageManager: models.Gradle,
			IsDirect:       false,
		},
	})
}
