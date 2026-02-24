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
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "maven_install.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/maven_install.json",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/maven_install.json/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/maven_install.json.bak",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.maven_install.json",
			want: false,
		},
		{
			name: "",
			path: "maven_install.lock",
			want: false,
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

func TestParseMavenInstall_InvalidJSON(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/invalid"))
	packages, err := java.ParseMavenInstall(path)

	testutil.ExpectErrContaining(t, err, "failed to decode maven_install.json")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_NullArtifact(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/null-artifact"))
	packages, err := java.ParseMavenInstall(path)

	testutil.ExpectErrContaining(t, err, "invalid maven_install.json: artifact")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_V1FormatUnsupported(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/v1-format"))
	packages, err := java.ParseMavenInstall(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParseMavenInstall_EmptyArtifacts(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/empty"))
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
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/one-pkg"))
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
				Line:     models.Position{Start: 3, End: 8},
				Column:   models.Position{Start: 5, End: 6},
			},
		},
	})
}

func TestParseMavenInstall_MultiplePackages(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/multiple-pkgs"))
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
				Line:     models.Position{Start: 3, End: 8},
				Column:   models.Position{Start: 5, End: 6},
			},
		},
		{
			Name:           "org.slf4j:slf4j-api",
			Version:        "1.7.36",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 9, End: 14},
				Column:   models.Position{Start: 5, End: 6},
			},
		},
		{
			Name:           "com.fasterxml.jackson.core:jackson-databind",
			Version:        "2.14.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Filename: path,
				Line:     models.Position{Start: 15, End: 20},
				Column:   models.Position{Start: 5, End: 6},
			},
		},
	})
}

func TestParseMavenInstall_WithClassifier(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/with-classifier"))
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
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven-install/duplicate-normalized-name"))
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
