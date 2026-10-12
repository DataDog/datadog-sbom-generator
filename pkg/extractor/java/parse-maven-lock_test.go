package java_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
)

func TestMavenLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/pom.xml/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/pom.xml.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.pom.xml",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := java.MavenLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseMavenLock(filepath.FromSlash("../fixtures/maven/does-not-exist"))

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_Invalid(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseMavenLock(filepath.FromSlash("../fixtures/maven/not-pom.txt"))

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_InvalidSyntax(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseMavenLock(filepath.FromSlash("../fixtures/maven/invalid-syntax.xml"))

	testutil.ExpectErrContaining(t, err, "XML syntax error")
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseMavenLock(filepath.FromSlash("../fixtures/maven/empty.xml"))
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_ShouldRemoveComments(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/with-comment.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 9},
				Column:   models.Position{Start: 10, End: 22},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 9, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 45, End: 50},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_ShouldTrim(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/with-spaces-and-tabs.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 10, End: 24},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 9, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.apache.maven:maven-artifact2",
			Version:        "3.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 19, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 9, End: 24},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 9, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 9, End: 12},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.apache.maven:maven-artifact3",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 29, End: 36},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 34, End: 34},
				Column:   models.Position{Start: 1, End: 16},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 31, End: 31},
				Column:   models.Position{Start: 10, End: 26},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 49, End: 49},
				Column:   models.Position{Start: 20, End: 25},
				Filename: path,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"org.apache.maven:maven-artifact3",
			"1.0.0",
			filePos(path, 41, 51, 11, 24),
			filePos(path, 46, 46, 27, 42),
			filePos(path, 43, 43, 1, 17),
			filePos(path, 49, 49, 20, 25),
		),
	})
}

func TestParseMavenLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/one-package.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 16, End: 32},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_WithExternalParent(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/with-external-parent.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.activemq:activemq-amqp",
			Version:        "5.16.5",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 13},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole:    models.LocationRoleManifest,
			VersionLocation: &models.FilePosition{},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 19, End: 32},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 16, End: 35},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_OnePackageWithMultipleVersionVariable(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/multiple-version-variables.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 13},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 32},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 40},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_TwoPackageWithMixedVersionDefinition(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/two-packages-mixed-version.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.3.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 38},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12-3.0",
			Version:        "1.7.25",
			Ecosystem:      models.EcosystemMaven,
			PackageManager: models.Maven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 19, End: 48},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 16, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/two-packages.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 11},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 28},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			Ecosystem:      models.EcosystemMaven,
			PackageManager: models.Maven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 12, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 19, End: 32},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 16, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
	})
}

func TestParseMavenLock_WithDependencyManagement(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/with-dependency-management.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 10},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 18, End: 30},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 19, End: 32},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 25},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 22},
				Filename: path,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(path, 20, 24, 7, 20),
			filePos(path, 22, 22, 21, 30),
			filePos(path, 21, 21, 18, 26),
			filePos(path, 23, 23, 18, 30),
		),
		mavenVersionConstraint(
			"com.google.code.findbugs:jsr305",
			"3.0.2",
			filePos(path, 25, 29, 7, 20),
			filePos(path, 27, 27, 21, 27),
			filePos(path, 26, 26, 18, 42),
			filePos(path, 28, 28, 18, 23),
		),
	})
}

func TestParseMavenLock_Interpolation(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/interpolation.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 23, End: 28},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 24, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 19, End: 29},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 25, End: 30},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:ranged-package",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 30, End: 33},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 32, End: 32},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 31, End: 31},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"org.mine:ranged-package",
			"9.4.35.v20201120",
			filePos(path, 38, 42, 7, 20),
			filePos(path, 40, 40, 21, 35),
			filePos(path, 39, 39, 18, 26),
			filePos(path, 14, 14, 20, 42),
		),
	})
}

func TestMavenLock_WithParent(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/parent.xml"))
	childPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/children/with-parent.xml"))
	packages, err := java.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 29},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 28, End: 28},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 16, End: 40},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 16, End: 25},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 28, End: 32},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 30, End: 30},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 37},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 19, End: 22},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 34, End: 34},
				Column:   models.Position{Start: 16, End: 23},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 12, End: 24},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(parentPath, 12, 16, 7, 20),
			filePos(parentPath, 14, 14, 21, 30),
			filePos(parentPath, 13, 13, 18, 26),
			filePos(parentPath, 15, 15, 18, 30),
		),
		mavenVersionConstraint(
			"com.google.code.findbugs:jsr305",
			"3.0.2",
			filePos(parentPath, 17, 21, 7, 20),
			filePos(parentPath, 19, 19, 21, 27),
			filePos(parentPath, 18, 18, 18, 42),
			filePos(parentPath, 20, 20, 18, 23),
		),
	})
}

func TestMavenLock_WithParentManagedDependencyOverride(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	childPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/children/with-parent-managed-override.xml"))
	packages, err := java.ParseMavenLock(childPath)
	require.NoError(t, err)

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			IsDirect:       true,
		},
		{
			// Resolved from the child's dependencyManagement override (4.1.100.Final), not
			// the parent's inherited pin (4.1.42.Final).
			Name:           "io.netty:netty-all",
			Version:        "4.1.100.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			IsDirect:       true,
		},
		{
			Name:                "io.netty:netty-all",
			Version:             "4.1.100.Final",
			PackageManager:      models.Maven,
			Ecosystem:           models.EcosystemMaven,
			IsVersionConstraint: true,
		},
		{
			Name:                "com.google.code.findbugs:jsr305",
			Version:             "3.0.2",
			PackageManager:      models.Maven,
			Ecosystem:           models.EcosystemMaven,
			IsVersionConstraint: true,
		},
	})
}

func TestMavenLock_WithParentUnresolvedManagedDependencyOverride(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	childPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/children/with-parent-unresolved-managed-override.xml"))
	packages, err := java.ParseMavenLock(childPath)
	require.NoError(t, err)

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			IsDirect:       true,
		},
		{
			// The child's override can't be resolved, so the parent's pin still applies.
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			IsDirect:       true,
		},
		{
			Name:                "io.netty:netty-all",
			Version:             "4.1.42.Final",
			PackageManager:      models.Maven,
			Ecosystem:           models.EcosystemMaven,
			IsVersionConstraint: true,
		},
		{
			Name:                "com.google.code.findbugs:jsr305",
			Version:             "3.0.2",
			PackageManager:      models.Maven,
			Ecosystem:           models.EcosystemMaven,
			IsVersionConstraint: true,
		},
	})
}

func TestMavenLock_WithParentDirOnly(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/pom.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/children/with-parent-dir-only.xml"))
	packages, err := java.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 25, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 16, End: 40},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 16, End: 25},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 28, End: 32},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 30, End: 30},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(parentPath, 11, 15, 7, 20),
			filePos(parentPath, 13, 13, 21, 30),
			filePos(parentPath, 12, 12, 18, 26),
			filePos(parentPath, 14, 14, 18, 30),
		),
		mavenVersionConstraint(
			"com.google.code.findbugs:jsr305",
			"3.0.2",
			filePos(parentPath, 16, 20, 7, 20),
			filePos(parentPath, 18, 18, 21, 27),
			filePos(parentPath, 17, 17, 18, 42),
			filePos(parentPath, 19, 19, 18, 23),
		),
	})
}

func TestMavenLock_WithParentWithoutRelativePath(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/pom.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/children/with-parent-without-relative-path.xml"))
	packages, err := java.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 25, End: 28},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 26, End: 26},
				Column:   models.Position{Start: 16, End: 40},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 18, End: 23},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 16},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 18, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 21},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 19, End: 32},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 18, End: 18},
				Column:   models.Position{Start: 16, End: 25},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 16, End: 22},
				Filename: childPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 22, End: 26},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 19, End: 28},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 23, End: 23},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "2.3.4",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 27, End: 31},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 29, End: 29},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 28, End: 28},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 25, End: 30},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(parentPath, 11, 15, 7, 20),
			filePos(parentPath, 13, 13, 21, 30),
			filePos(parentPath, 12, 12, 18, 26),
			filePos(parentPath, 14, 14, 18, 30),
		),
		mavenVersionConstraint(
			"com.google.code.findbugs:jsr305",
			"3.0.2",
			filePos(parentPath, 16, 20, 7, 20),
			filePos(parentPath, 18, 18, 21, 27),
			filePos(parentPath, 17, 17, 18, 42),
			filePos(parentPath, 19, 19, 18, 23),
		),
	})
}

func TestMavenLock_WithParent_Child_Project(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	parentPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/parent-project-version.xml"))
	childPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/children/with-parent-child-project-version.xml"))
	packages, err := java.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "1.0-CHILD-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 15},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 13, End: 13},
				Column:   models.Position{Start: 19, End: 25},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 40},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 12, End: 30},
				Filename: childPath,
			},
			IsDirect: true,
		},
	})
}

func TestMavenLock_WithMultipleParents(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/parent.xml"))
	parentPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/children/with-parent.xml"))
	childPath := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/children/with-multiple-parent.xml"))
	packages, err := java.ParseMavenLock(childPath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "3.0.2",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 26, End: 29},
				Column:   models.Position{Start: 5, End: 18},
				Filename: rootPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 28, End: 28},
				Column:   models.Position{Start: 19, End: 25},
				Filename: rootPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 27, End: 27},
				Column:   models.Position{Start: 16, End: 40},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 18, End: 23},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 28},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 24},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 18, End: 30},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.slf4j:slf4j-log4j12",
			Version:        "1.7.25",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 18, End: 22},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 19, End: 32},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 16, End: 25},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 21, End: 21},
				Column:   models.Position{Start: 16, End: 22},
				Filename: parentPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:mypackage",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 23, End: 27},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 25, End: 25},
				Column:   models.Position{Start: 19, End: 28},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 24, End: 24},
				Column:   models.Position{Start: 16, End: 24},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 23, End: 28},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "org.mine:my.package",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: childPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 29},
				Filename: childPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 24},
				Filename: childPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 20, End: 42},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 37},
				Column:   models.Position{Start: 5, End: 18},
				Filename: parentPath,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 19, End: 22},
				Filename: parentPath,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 34, End: 34},
				Column:   models.Position{Start: 16, End: 23},
				Filename: parentPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 12, End: 24},
				Filename: rootPath,
			},
			IsDirect: true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(rootPath, 12, 16, 7, 20),
			filePos(rootPath, 14, 14, 21, 30),
			filePos(rootPath, 13, 13, 18, 26),
			filePos(rootPath, 15, 15, 18, 30),
		),
		mavenVersionConstraint(
			"com.google.code.findbugs:jsr305",
			"3.0.2",
			filePos(rootPath, 17, 21, 7, 20),
			filePos(rootPath, 19, 19, 21, 27),
			filePos(rootPath, 18, 18, 18, 42),
			filePos(rootPath, 20, 20, 18, 23),
		),
	})
}

func TestMavenLockDependency_ResolveVersion(t *testing.T) {
	t.Parallel()

	type fields struct {
		Version models.StringWithPosition
	}
	type args struct {
		lockfile java.MavenLockFile
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		// 1.0: Soft requirement for 1.0. Use 1.0 if no other version appears earlier in the dependency tree.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "1.0",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "1.0",
		},
		// [1.0]: Hard requirement for 1.0. Use 1.0 and only 1.0.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "[1.0]",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "1.0",
		},
		// (,1.0]: Hard requirement for any version <= 1.0.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "(,1.0]",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "",
		},
		// [1.2,1.3]: Hard requirement for any version between 1.2 and 1.3 inclusive.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "[1.2,1.3]",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "1.2",
		},
		// [1.0,2.0): 1.0 <= x < 2.0; Hard requirement for any version between 1.0 inclusive and 2.0 exclusive.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "[1.0,2.0)",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "1.0",
		},
		// [1.5,): Hard requirement for any version greater than or equal to 1.5.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "[1.5,)",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "1.5",
		},
		// (,1.0],[1.2,): Hard requirement for any version less than or equal to 1.0 than or greater than or equal to 1.2, but not 1.1.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "(,1.0],[1.2,)",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "",
		},
		// (,1.1),(1.1,): Hard requirement for any version except 1.1; for example because 1.1 has a critical vulnerability.
		{
			name: "",
			fields: fields{Version: models.StringWithPosition{
				Value: "(,1.1),(1.1,)",
			}},
			args: args{lockfile: java.MavenLockFile{}},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mld := java.MavenLockDependency{
				Version: tt.fields.Version,
			}
			if got, _ := mld.ResolveVersion(tt.args.lockfile, testutil.GetTestContext()); got != tt.want {
				t.Errorf("ResolveVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseMavenLock_WithScope(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/with-scope.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "abc:xyz",
			Version:        "1.2.3",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 3, End: 8},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 16, End: 19},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			IsDirect: true,
		},
		{
			Name:           "junit:junit",
			Version:        "4.12",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 9, End: 14},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 12, End: 12},
				Column:   models.Position{Start: 16, End: 20},
				Filename: path,
			},
			DepGroups: []string{"test"},
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_WithUnusedDependencyManagementDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/with-unused-dependency-management.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 17, End: 21},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 19, End: 19},
				Column:   models.Position{Start: 19, End: 28},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 18, End: 18},
				Column:   models.Position{Start: 16, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 20, End: 20},
				Column:   models.Position{Start: 16, End: 28},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		mavenVersionConstraint(
			"io.unused:unused-artifact",
			"1.0.0",
			filePos(path, 8, 12, 7, 20),
			filePos(path, 10, 10, 21, 36),
			filePos(path, 9, 9, 18, 27),
			filePos(path, 11, 11, 18, 23),
		),
	})
}

func TestParseMavenLock_WithOverriddenDependencyVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/with-overridden-dependency-version.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "junit:junit",
			Version:        "4.12",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 18},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 16, End: 16},
				Column:   models.Position{Start: 19, End: 24},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 17, End: 17},
				Column:   models.Position{Start: 16, End: 20},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		mavenVersionConstraint(
			"junit:junit",
			"3.0",
			filePos(path, 5, 9, 7, 20),
			filePos(path, 7, 7, 21, 26),
			filePos(path, 6, 6, 18, 23),
			filePos(path, 8, 8, 18, 21),
		),
	})
}

func TestParseMavenLock_WithProjectVersionProperty(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/with-project-version-property.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "dev.foo:bar",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 8, End: 12},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 16, End: 23},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 24},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "dev.bar:foo",
			Version:        "1.0-SNAPSHOT",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 13, End: 17},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 15, End: 15},
				Column:   models.Position{Start: 19, End: 22},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 16, End: 23},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 12, End: 24},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
	})
}

func TestParseMavenLock_ResolveProperties(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/resolve-properties.xml"))
	packages, err := java.ParseMavenLock(path)
	require.NoError(t, err)

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "io.netty:netty-all",
			Version:        "4.1.42.Final",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 27, End: 30},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 21, End: 30},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 18, End: 26},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 4, End: 4},
				Column:   models.Position{Start: 20, End: 32},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "com.google.code.findbugs:jsr305",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 31, End: 35},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 24, End: 30},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 7, End: 7},
				Column:   models.Position{Start: 21, End: 45},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		{
			Name:           "io.ktor:ktor-server-netty-jvm",
			Version:        "9.4.35.v20201120",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			Commit:         "",
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 36, End: 40},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 38, End: 38},
				Column:   models.Position{Start: 19, End: 35},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 17, End: 24},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 3, End: 3},
				Column:   models.Position{Start: 20, End: 42},
				Filename: path,
			},
			DepGroups: nil,
			IsDirect:  true,
		},
		mavenVersionConstraint(
			"io.netty:netty-all",
			"4.1.42.Final",
			filePos(path, 18, 22, 7, 20),
			filePos(path, 20, 20, 21, 30),
			filePos(path, 19, 19, 18, 26),
			filePos(path, 4, 4, 20, 32),
		),
	})
}

func TestParseMavenLock_NoVersion(t *testing.T) {
	t.Parallel()
	lockfileRelativePath := "../fixtures/maven/no-version.xml"
	packages, err := java.ParseMavenLock(lockfileRelativePath)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			IsDirect:       true,
		},
	})
}

func TestParseMavenLock_SpringRemote(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.Join(dir, filepath.FromSlash("../fixtures/maven/spring-remote.xml"))
	packages, err := java.ParseMavenLock(path)
	require.NoError(t, err)

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.springframework.boot:spring-boot-starter-test",
			Version:        "3.4.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 38, End: 42},
				Column:   models.Position{Start: 3, End: 16},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 40, End: 40},
				Column:   models.Position{Start: 16, End: 40},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 39, End: 39},
				Column:   models.Position{Start: 13, End: 37},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{},
			DepGroups:       []string{"test"},
			IsDirect:        true,
		},
		{
			Name:           "org.springframework.boot:spring-boot-starter-web",
			Version:        "3.4.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 33, End: 36},
				Column:   models.Position{Start: 3, End: 16},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 35, End: 35},
				Column:   models.Position{Start: 16, End: 39},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 34, End: 34},
				Column:   models.Position{Start: 13, End: 37},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{},
			IsDirect:        true,
		},
	})
}

func TestParseMavenLock_SkipsImportedBOM(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/dependency-management-import.xml"))
	packages, err := java.ParseMavenLock(path)
	require.NoError(t, err)

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_SkipsManagedDependencyWithoutVersion(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	require.NoError(t, err)

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/dependency-management-no-version.xml"))
	packages, err := java.ParseMavenLock(path)
	require.NoError(t, err)

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseMavenLock_TwoExclusions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/maven/one-package-two-exclusions.xml"))
	packages, err := java.ParseMavenLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{
		{
			Name:           "org.apache.maven:maven-artifact",
			Version:        "1.0.0",
			PackageManager: models.Maven,
			Ecosystem:      models.EcosystemMaven,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 7, End: 21},
				Column:   models.Position{Start: 5, End: 18},
				Filename: path,
			},
			LocationRole: models.LocationRoleManifest,
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 9, End: 9},
				Column:   models.Position{Start: 19, End: 33},
				Filename: path,
			},
			NamespaceLocation: &models.FilePosition{
				Line:     models.Position{Start: 8, End: 8},
				Column:   models.Position{Start: 16, End: 32},
				Filename: path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 21},
				Filename: path,
			},
			IsDirect: true,
			Exclusions: []string{
				"com.example:not-wanted", "com.example:*",
			},
		},
	})
}

func mavenVersionConstraint(name, version string, block, nameLoc, namespaceLoc, versionLoc models.FilePosition) extractor.PackageDetails {
	return extractor.PackageDetails{
		Name:                name,
		Version:             version,
		PackageManager:      models.Maven,
		Ecosystem:           models.EcosystemMaven,
		BlockLocation:       block,
		LocationRole:        models.LocationRoleManifest,
		NameLocation:        &nameLoc,
		NamespaceLocation:   &namespaceLoc,
		VersionLocation:     &versionLoc,
		IsVersionConstraint: true,
	}
}

func filePos(filename string, lineStart, lineEnd, colStart, colEnd int) models.FilePosition {
	return models.FilePosition{
		Line:     models.Position{Start: lineStart, End: lineEnd},
		Column:   models.Position{Start: colStart, End: colEnd},
		Filename: filename,
	}
}
