package java_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestJarPomPropertiesExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty path",
			path: "",
			want: false,
		},
		{
			name: "filename only",
			path: "library.jar",
			want: true,
		},
		{
			name: "nested path",
			path: "path/to/my/library.jar",
			want: true,
		},
		{
			name: "filename is directory component",
			path: "path/to/my/library.jar/file",
			want: false,
		},
		{
			name: "backup extension",
			path: "library.jar.bak",
			want: false,
		},
		{
			name: "war file",
			path: "library.war",
			want: false,
		},
		{
			name: "pom.xml",
			path: "pom.xml",
			want: false,
		},
		{
			name: "uppercase JAR",
			path: "library.JAR",
			want: false,
		},
		{
			name: "directory-like path ending in .jar/",
			path: "path/to/lib.jar/",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := java.JarPomPropertiesExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("ShouldExtract(%q) got = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestJarPomPropertiesExtractor_IsOfficiallySupported(t *testing.T) {
	t.Parallel()

	e := java.JarPomPropertiesExtractor{}
	if e.IsOfficiallySupported() {
		t.Error("expected IsOfficiallySupported() to return false for opt-in parser")
	}
}

func TestJarPomPropertiesExtractor_Registration(t *testing.T) {
	t.Parallel()

	// The java package's init() registers the extractor.
	// Importing java (done above) triggers registration.
	if !lockfile.IsSupportedExtractor(models.JarFilePath.String()) {
		t.Error("expected extractor to be registered as \"jar\"")
	}
}

func TestParseJarPomProperties_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseJarPomProperties("../fixtures/jar/does-not-exist.jar")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseJarPomProperties_NotAJar(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/not-a-jar")
	packages, err := java.ParseJarPomProperties(path)

	testutil.ExpectErrIs(t, err, lockfile.ErrIncompatibleFileFormat)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseJarPomProperties_NoPomProperties(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/no-pom-properties.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseJarPomProperties_OnePackage(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/one-package.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:my-lib",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_MultiplePackages(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/multiple-packages.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:lib-a",
			Version:        "2.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
		{
			Name:           "org.other:lib-b",
			Version:        "3.1.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_MalformedPomProperties(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/malformed-pom-properties.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Malformed pom.properties (missing groupId) should be skipped gracefully
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

// ============================================================================
// MANIFEST.MF Fallback Integration Tests
// ============================================================================

func TestParseJarPomProperties_ManifestFallback_Bouncycastle(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/bcprov-jdk18on-1.78.1.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.bouncycastle:bcprov-jdk18on",
			Version:        "1.78.1",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_ManifestFallback_NoBundleSymbolicName(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/manifest-no-bsn-1.0.0.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// No Bundle-SymbolicName means no groupId can be inferred -> no package emitted
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseJarPomProperties_ManifestFallback_VersionPriority(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// Bundle-Version=1.5.0, Implementation-Version=1.6.0, filename=2.0.0
	// Since they disagree, filename version wins
	path := filepath.Join(dir, "../fixtures/jar/mylib-2.0.0.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:mylib",
			Version:        "2.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_ManifestFallback_SingletonDirective(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/jar/runtime-3.26.0.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "org.eclipse.core:runtime",
			Version:        "3.26.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_PomPropertiesTakesPrecedence(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// JAR has both pom.properties and MANIFEST.MF - pom.properties should win
	path := filepath.Join(dir, "../fixtures/jar/has-both-1.0.0.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:has-both",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}

func TestParseJarPomProperties_ManifestFallback_VersionAgreement(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// Bundle-Version == Implementation-Version -> high confidence, use it
	path := filepath.Join(dir, "../fixtures/jar/gson-2.10.1.jar")
	packages, err := java.ParseJarPomProperties(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google:gson",
			Version:        "2.10.1",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		},
	})
}
