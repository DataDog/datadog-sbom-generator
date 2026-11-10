package java_test

import (
	"archive/zip"
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// buildZip returns a zip archive containing the given entries (name -> content).
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		content := entries[name]
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

func pomProps(artifact, version string) map[string][]byte {
	const group = "com.example"

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

	inner := buildZip(t, pomProps("a", "1.0.0"))
	war := buildZip(t, with(pomProps("webapp", "9.9.9"), "WEB-INF/lib/a-1.0.0.jar", inner))

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

	jar := buildZip(t, pomProps("deep", "2.0.0"))
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

	inner := buildZip(t, pomProps("b", "3.0.0"))
	fat := buildZip(t, with(pomProps("boot-app", "1.2.3"), "BOOT-INF/lib/b-3.0.0.jar", inner))

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

	good := buildZip(t, pomProps("good", "1.0.0"))
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

// parseWithWarnings extracts an archive and returns its packages and the warnings emitted.
func parseWithWarnings(t *testing.T, p string) ([]extractor.PackageDetails, string) {
	t.Helper()

	var stderr bytes.Buffer
	context := extractor.ScanContext{Reporter: reporter.NewCycloneDXReporter(&bytes.Buffer{}, &stderr, reporter.WarnLevel)}

	packages, err := extractor.ExtractFromFileWithContext(p, java.JarPomPropertiesExtractor{}, context)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	return packages, stderr.String()
}

// nestedWar wraps a JAR declaring com.example:deep in `levels` levels of
// nested WARs (the JAR sits at nesting depth `levels`) next to a sibling JAR
// at depth 1.
func nestedWar(t *testing.T, levels int) []byte {
	t.Helper()

	archive := buildZip(t, pomProps("deep", "1.0.0"))
	name := "deep-1.0.0.jar"
	for range levels - 1 {
		archive = buildZip(t, map[string][]byte{name: archive})
		name = "level.war"
	}
	sibling := buildZip(t, pomProps("sibling", "1.0.0"))

	return buildZip(t, map[string][]byte{name: archive, "sibling-1.0.0.jar": sibling})
}

func TestParseJarPomProperties_MaxDepthAccepted(t *testing.T) {
	t.Parallel()

	packages, _ := parseWithWarnings(t, writeArchive(t, "app.war", nestedWar(t, 5)))

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:deep", "1.0.0"),
		mavenPkg("com.example:sibling", "1.0.0"),
	})
}

func TestParseJarPomProperties_BeyondMaxDepthSkipped(t *testing.T) {
	t.Parallel()

	packages, warnings := parseWithWarnings(t, writeArchive(t, "app.war", nestedWar(t, 6)))

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:sibling", "1.0.0"),
	})
	if !strings.Contains(warnings, "maximum nesting depth") || !strings.Contains(warnings, "!/deep-1.0.0.jar") {
		t.Errorf("expected depth warning naming the nested path, got %q", warnings)
	}
}

//nolint:paralleltest // mutates the global nested archive size limit
func TestParseJarPomProperties_OversizedNestedEntrySkipped(t *testing.T) {
	small := buildZip(t, pomProps("small", "1.0.0"))
	big := buildZip(t, with(pomProps("big", "1.0.0"), "padding", bytes.Repeat([]byte("x"), 4096)))
	t.Cleanup(java.SetMaxNestedArchiveSize(uint64(len(small))))

	war := buildZip(t, map[string][]byte{
		"WEB-INF/lib/big-1.0.0.jar":   big,
		"WEB-INF/lib/small-1.0.0.jar": small,
	})
	warPath := writeArchive(t, "app.war", war)

	packages, warnings := parseWithWarnings(t, warPath)

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:small", "1.0.0"),
	})
	if !strings.Contains(warnings, warPath+"!/WEB-INF/lib/big-1.0.0.jar") || !strings.Contains(warnings, "exceeds limit") {
		t.Errorf("expected size warning naming the nested path, got %q", warnings)
	}
}

//nolint:paralleltest // mutates the global nested archive budget
func TestParseJarPomProperties_NestedArchiveBudgetExhausted(t *testing.T) {
	first := buildZip(t, pomProps("first", "1.0.0"))
	second := buildZip(t, pomProps("second", "1.0.0"))
	chain := buildZip(t, map[string][]byte{"WEB-INF/lib/second-1.0.0.jar": second})
	// Budget fits the first JAR but not the chained WAR that follows it.
	t.Cleanup(java.SetMaxNestedArchiveBudget(uint64(len(first)) + uint64(len(chain)) - 1))

	ear := buildZip(t, map[string][]byte{
		"a-first-1.0.0.jar": first,
		"b-chain.war":       chain,
	})
	earPath := writeArchive(t, "app.ear", ear)

	packages, warnings := parseWithWarnings(t, earPath)

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		mavenPkg("com.example:first", "1.0.0"),
	})
	if !strings.Contains(warnings, earPath+"!/b-chain.war") || !strings.Contains(warnings, "budget exhausted") {
		t.Errorf("expected budget warning naming the nested path, got %q", warnings)
	}
}
