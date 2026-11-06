package java_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// buildZip returns a zip archive containing the given entries (name -> content).
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("could not create zip entry %s: %v", name, err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatalf("could not write zip entry %s: %v", name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("could not close zip: %v", err)
	}

	return buf.Bytes()
}

func pomProps(group, artifact, version string) map[string][]byte {
	return map[string][]byte{
		"META-INF/maven/" + group + "/" + artifact + "/pom.properties": []byte(
			"groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n"),
	}
}

func with(entries map[string][]byte, name string, content []byte) map[string][]byte {
	entries[name] = content
	return entries
}

func writeArchive(t *testing.T, name string, content []byte) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("could not write %s: %v", p, err)
	}

	return p
}

func mavenPkg(name, version string) extractor.PackageDetails {
	return extractor.PackageDetails{
		Name:           name,
		Version:        version,
		PackageManager: models.Maven,
		Ecosystem:      models.EcosystemMaven,
		Opaque:         true,
		IsDirect:       true,
	}
}

func TestParseJarPomProperties_WarReportsOnlyInnerJars(t *testing.T) {
	t.Parallel()

	inner := buildZip(t, pomProps("com.example", "a", "1.0.0"))
	war := buildZip(t, with(pomProps("com.example", "webapp", "9.9.9"), "WEB-INF/lib/a-1.0.0.jar", inner))

	packages, err := java.ParseJarPomProperties(writeArchive(t, "app.war", war))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:a", "1.0.0"),
	})
}

func TestParseJarPomProperties_EarWarJar(t *testing.T) {
	t.Parallel()

	jar := buildZip(t, pomProps("com.example", "deep", "2.0.0"))
	war := buildZip(t, map[string][]byte{"WEB-INF/lib/deep-2.0.0.jar": jar})
	ear := buildZip(t, map[string][]byte{"web.war": war})

	packages, err := java.ParseJarPomProperties(writeArchive(t, "app.ear", ear))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:deep", "2.0.0"),
	})
}

func TestParseJarPomProperties_FatJar(t *testing.T) {
	t.Parallel()

	inner := buildZip(t, pomProps("com.example", "b", "3.0.0"))
	fat := buildZip(t, with(pomProps("com.example", "boot-app", "1.2.3"), "BOOT-INF/lib/b-3.0.0.jar", inner))

	packages, err := java.ParseJarPomProperties(writeArchive(t, "boot-app-1.2.3.jar", fat))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:boot-app", "1.2.3"),
		mavenPkg("com.example:b", "3.0.0"),
	})
}

func TestParseJarPomProperties_NestedManifestFallbackUsesEntryName(t *testing.T) {
	t.Parallel()

	inner := buildZip(t, map[string][]byte{
		"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\r\nBundle-SymbolicName: org.bouncycastle.bcprov\r\nBundle-Version: 1.78.1\r\n"),
	})
	war := buildZip(t, map[string][]byte{"WEB-INF/lib/bcprov-jdk18on-1.78.1.jar": inner})

	packages, err := java.ParseJarPomProperties(writeArchive(t, "app.war", war))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	if len(packages) != 1 || packages[0].Version != "1.78.1" {
		t.Fatalf("expected one package from manifest fallback with version 1.78.1, got %+v", packages)
	}
}

func TestParseJarPomProperties_CorruptNestedJarSkipped(t *testing.T) {
	t.Parallel()

	good := buildZip(t, pomProps("com.example", "good", "1.0.0"))
	war := buildZip(t, map[string][]byte{
		"WEB-INF/lib/broken.jar":     []byte("not a zip"),
		"WEB-INF/lib/good-1.0.0.jar": good,
	})

	packages, err := java.ParseJarPomProperties(writeArchive(t, "app.war", war))
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:good", "1.0.0"),
	})
}

func TestParseJarPomProperties_NotAZipWar(t *testing.T) {
	t.Parallel()

	packages, err := java.ParseJarPomProperties(writeArchive(t, "app.war", []byte("not a zip")))

	testutil.ExpectErrIs(t, err, extractor.ErrIncompatibleFileFormat)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}
