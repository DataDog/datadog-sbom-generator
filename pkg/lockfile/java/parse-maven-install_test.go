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

func TestMavenInstallExtractor_ShouldExtract(t *testing.T) {
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
			path: "maven_install.json",
			want: true,
		},
		{
			name: "nested path",
			path: "path/to/my/maven_install.json",
			want: true,
		},
		{
			name: "filename is directory component",
			path: "path/to/my/maven_install.json/file",
			want: false,
		},
		{
			name: "backup extension",
			path: "path/to/my/maven_install.json.bak",
			want: false,
		},
		{
			name: "dot-separated path",
			path: "path.to.my.maven_install.json",
			want: true,
		},
		{
			name: "wrong extension",
			path: "maven_install.lock",
			want: false,
		},
		{
			name: "custom repo name prefix",
			path: "foo_maven_install.json",
			want: true,
		},
		{
			name: "custom repo name prefix nested",
			path: "path/to/bar_maven_install.json",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := java.MavenInstallExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("ShouldExtract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenInstall_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseMavenInstall("../fixtures/maven-install/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_EmptyFile(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/empty-file")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_InvalidJSON(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/invalid")
	packages, err := java.ParseMavenInstall(path)

	testutil.ExpectErrContaining(t, err, "could not decode")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_NullArtifact(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/null-artifact")
	packages, err := java.ParseMavenInstall(path)

	testutil.ExpectErrContaining(t, err, "invalid maven_install.json: artifact")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_V1OnePackage(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/v1-one-pkg")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.guava:guava",
			Version:        "31.1-jre",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestParseMavenInstall_V1MultiplePackages(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/v1-multiple-pkgs")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.fasterxml.jackson.core:jackson-databind",
			Version:        "2.14.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "com.google.guava:guava",
			Version:        "31.1-jre",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "io.netty:netty-tcnative-boringssl-static",
			Version:        "2.0.61.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.slf4j:slf4j-api",
			Version:        "1.7.36",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestParseMavenInstall_V1WithAtPackaging(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/v1-at-packaging")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:pom-coord",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "com.example:short-classifier",
			Version:        "2.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "com.example:simple",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "com.example:with-classifier",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestParseMavenInstall_EmptyArtifacts(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/empty")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_OnePackage(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/one-pkg")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.guava:guava",
			Version:        "31.1-jre",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 4, End: 10},
				Column:   models.Position{Start: 5, End: 6},
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseMavenInstall_MultiplePackages(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/multiple-pkgs")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.fasterxml.jackson.core:jackson-databind",
			Version:        "2.14.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 4, End: 10},
				Column:   models.Position{Start: 5, End: 6},
			},
			LocationRole: models.LocationRoleLockfile,
		},
		{
			Name:           "com.google.guava:guava",
			Version:        "31.1-jre",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 11, End: 17},
				Column:   models.Position{Start: 5, End: 6},
			},
			LocationRole: models.LocationRoleLockfile,
		},
		{
			Name:           "org.slf4j:slf4j-api",
			Version:        "1.7.36",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 18, End: 24},
				Column:   models.Position{Start: 5, End: 6},
			},
			LocationRole: models.LocationRoleLockfile,
		},
	})
}

func TestParseMavenInstall_WithClassifier(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/with-classifier")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.google.guava:guava",
			Version:        "31.1-jre",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "io.netty:netty-tcnative-boringssl-static",
			Version:        "2.0.61.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
		{
			Name:           "org.graalvm.js:js-community",
			Version:        "24.2.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}

func TestParseMavenInstall_DuplicateNormalizedName(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, "../fixtures/maven-install/duplicate-normalized-name")
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "com.example:demo",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
		},
	})
}
