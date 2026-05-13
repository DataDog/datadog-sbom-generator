package java

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
)

// ============================================================================
// T-1: parseJarFilename tests
// ============================================================================

func TestParseJarFilename(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		filename       string
		wantArtifactID string
		wantVersion    string
	}{
		{
			name:           "standard Maven artifact",
			filename:       "commons-lang3-3.12.0.jar",
			wantArtifactID: "commons-lang3",
			wantVersion:    "3.12.0",
		},
		{
			name:           "version with qualifier",
			filename:       "spring-core-5.3.0-SNAPSHOT.jar",
			wantArtifactID: "spring-core",
			wantVersion:    "5.3.0-SNAPSHOT",
		},
		{
			name:           "simple artifact with version",
			filename:       "gson-2.10.1.jar",
			wantArtifactID: "gson",
			wantVersion:    "2.10.1",
		},
		{
			name:           "no version - no match",
			filename:       "some-lib.jar",
			wantArtifactID: "",
			wantVersion:    "",
		},
		{
			name:           "no extension",
			filename:       "lib-1.0.0",
			wantArtifactID: "",
			wantVersion:    "",
		},
		{
			name:           "version with dots",
			filename:       "bcprov-jdk18on-1.78.1.jar",
			wantArtifactID: "bcprov-jdk18on",
			wantVersion:    "1.78.1",
		},
		{
			name:           "single digit version",
			filename:       "lib-1.jar",
			wantArtifactID: "lib",
			wantVersion:    "1",
		},
		{
			name:           "empty filename",
			filename:       "",
			wantArtifactID: "",
			wantVersion:    "",
		},
		{
			name:           "just .jar",
			filename:       ".jar",
			wantArtifactID: "",
			wantVersion:    "",
		},
		{
			name:           "version starts with digit after hyphen",
			filename:       "log4j-api-2.17.1.jar",
			wantArtifactID: "log4j-api",
			wantVersion:    "2.17.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotArtifact, gotVersion := parseJarFilename(tt.filename)
			if gotArtifact != tt.wantArtifactID {
				t.Errorf("parseJarFilename(%q) artifactId = %q, want %q", tt.filename, gotArtifact, tt.wantArtifactID)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("parseJarFilename(%q) version = %q, want %q", tt.filename, gotVersion, tt.wantVersion)
			}
		})
	}
}

// ============================================================================
// T-1: cleanBundleSymbolicName tests
// ============================================================================

func TestCleanBundleSymbolicName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "no directives",
			raw:  "org.bouncycastle.bcprov-jdk18on",
			want: "org.bouncycastle.bcprov-jdk18on",
		},
		{
			name: "singleton directive",
			raw:  "org.eclipse.core.runtime;singleton:=true",
			want: "org.eclipse.core.runtime",
		},
		{
			name: "multiple directives",
			raw:  "com.example.bundle;singleton:=true;lazy:=true",
			want: "com.example.bundle",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "whitespace around value",
			raw:  "  org.example.bundle  ",
			want: "org.example.bundle",
		},
		{
			name: "whitespace before semicolon",
			raw:  "org.example.bundle ;singleton:=true",
			want: "org.example.bundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cleanBundleSymbolicName(tt.raw)
			if got != tt.want {
				t.Errorf("cleanBundleSymbolicName(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// ============================================================================
// T-1: cleanName tests
// ============================================================================

func TestCleanName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "simple name",
			raw:  "Gson",
			want: "gson",
		},
		{
			name: "name with spaces",
			raw:  "Apache Commons Lang",
			want: "apache-commons-lang",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "already clean",
			raw:  "my-lib",
			want: "my-lib",
		},
		{
			name: "underscores preserved",
			raw:  "my_lib",
			want: "my_lib",
		},
		{
			name: "dots preserved",
			raw:  "org.eclipse.osgi",
			want: "org.eclipse.osgi",
		},
		{
			name: "mixed case with special chars",
			raw:  "Bouncy Castle Provider",
			want: "bouncy-castle-provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cleanName(tt.raw)
			if got != tt.want {
				t.Errorf("cleanName(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// ============================================================================
// T-1: parseManifestAttributes tests
// ============================================================================

// createTestJar creates an in-memory JAR (ZIP) with a MANIFEST.MF containing the given content.
func createTestJar(t *testing.T, manifestContent string) *zip.Reader {
	t.Helper()

	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f, err := w.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("failed to create MANIFEST.MF in test jar: %v", err)
	}

	_, err = f.Write([]byte(manifestContent))
	if err != nil {
		t.Fatalf("failed to write MANIFEST.MF content: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close test jar: %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to open test jar: %v", err)
	}

	return reader
}

func TestParseManifestAttributes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		manifest          string
		wantBSN           string
		wantBundleName    string
		wantBundleVersion string
		wantImplTitle     string
		wantImplVersion   string
		wantErr           bool
	}{
		{
			name: "full OSGi manifest",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Bundle-SymbolicName: org.bouncycastle.bcprov-jdk18on\r\n" +
				"Bundle-Name: bcprov\r\n" +
				"Bundle-Version: 1.78.1\r\n" +
				"Implementation-Title: bcprov\r\n" +
				"Implementation-Version: 1.78.1\r\n",
			wantBSN:           "org.bouncycastle.bcprov-jdk18on",
			wantBundleName:    "bcprov",
			wantBundleVersion: "1.78.1",
			wantImplTitle:     "bcprov",
			wantImplVersion:   "1.78.1",
		},
		{
			name:              "only manifest version",
			manifest:          "Manifest-Version: 1.0\r\n",
			wantBSN:           "",
			wantBundleName:    "",
			wantBundleVersion: "",
			wantImplTitle:     "",
			wantImplVersion:   "",
		},
		{
			name: "BSN with singleton directive",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Bundle-SymbolicName: org.eclipse.core.runtime;singleton:=true\r\n" +
				"Bundle-Version: 3.26.0\r\n",
			wantBSN:           "org.eclipse.core.runtime;singleton:=true",
			wantBundleName:    "",
			wantBundleVersion: "3.26.0",
			wantImplTitle:     "",
			wantImplVersion:   "",
		},
		{
			name: "implementation attributes only",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Implementation-Title: Gson\r\n" +
				"Implementation-Version: 2.10.1\r\n",
			wantBSN:           "",
			wantBundleName:    "",
			wantBundleVersion: "",
			wantImplTitle:     "Gson",
			wantImplVersion:   "2.10.1",
		},
		{
			name: "continuation lines",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Bundle-SymbolicName: org.example.very.long.symbolic\r\n" +
				" .name.continued\r\n" +
				"Bundle-Version: 1.0.0\r\n",
			wantBSN:           "org.example.very.long.symbolic.name.continued",
			wantBundleName:    "",
			wantBundleVersion: "1.0.0",
			wantImplTitle:     "",
			wantImplVersion:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reader := createTestJar(t, tt.manifest)
			bsn, bundleName, bundleVersion, implTitle, implVersion, err := parseManifestAttributes(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseManifestAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if bsn != tt.wantBSN {
				t.Errorf("BSN = %q, want %q", bsn, tt.wantBSN)
			}
			if bundleName != tt.wantBundleName {
				t.Errorf("BundleName = %q, want %q", bundleName, tt.wantBundleName)
			}
			if bundleVersion != tt.wantBundleVersion {
				t.Errorf("BundleVersion = %q, want %q", bundleVersion, tt.wantBundleVersion)
			}
			if implTitle != tt.wantImplTitle {
				t.Errorf("ImplTitle = %q, want %q", implTitle, tt.wantImplTitle)
			}
			if implVersion != tt.wantImplVersion {
				t.Errorf("ImplVersion = %q, want %q", implVersion, tt.wantImplVersion)
			}
		})
	}
}

func TestParseManifestAttributes_NoManifest(t *testing.T) {
	t.Parallel()

	// Create a JAR with no MANIFEST.MF
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)

	f, err := w.Create("some/other/file.txt")
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}

	fmt.Fprintln(f, "hello")

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close jar: %v", err)
	}

	reader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("failed to open jar: %v", err)
	}

	bsn, bundleName, bundleVersion, implTitle, implVersion, err := parseManifestAttributes(reader)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// All should be empty when no MANIFEST.MF exists
	if bsn != "" || bundleName != "" || bundleVersion != "" || implTitle != "" || implVersion != "" {
		t.Errorf("expected all empty, got bsn=%q bundleName=%q bundleVersion=%q implTitle=%q implVersion=%q",
			bsn, bundleName, bundleVersion, implTitle, implVersion)
	}
}

// ============================================================================
// T-2: parseGroupID tests
// ============================================================================

func TestParseGroupId(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		bundleSymbolicName string
		bundleName         string
		filenameArtifact   string
		want               string
	}{
		{
			name:               "bouncycastle - filename candidate matches suffix",
			bundleSymbolicName: "org.bouncycastle.bcprov-jdk18on",
			bundleName:         "",
			filenameArtifact:   "bcprov-jdk18on",
			want:               "org.bouncycastle",
		},
		{
			name:               "google gson - cleaned bundle name matches",
			bundleSymbolicName: "com.google.gson",
			bundleName:         "Gson",
			filenameArtifact:   "gson",
			want:               "com.google",
		},
		{
			name:               "eclipse osgi - no candidate match, fallback to BSN",
			bundleSymbolicName: "org.eclipse.osgi",
			bundleName:         "",
			filenameArtifact:   "org.eclipse.osgi",
			want:               "org.eclipse.osgi",
		},
		{
			name:               "short BSN - len <= 5, fallback to BSN",
			bundleSymbolicName: "ab.cd",
			bundleName:         "",
			filenameArtifact:   "cd",
			want:               "ab.cd",
		},
		{
			name:               "BSN with no dots - fallback to BSN",
			bundleSymbolicName: "mybundle",
			bundleName:         "",
			filenameArtifact:   "mybundle",
			want:               "mybundle",
		},
		{
			name:               "empty BSN",
			bundleSymbolicName: "",
			bundleName:         "",
			filenameArtifact:   "somelib",
			want:               "",
		},
		{
			name:               "filename matches but bundleName also matches - filename tried first",
			bundleSymbolicName: "org.apache.commons-lang3",
			bundleName:         "",
			filenameArtifact:   "commons-lang3",
			want:               "org.apache",
		},
		{
			name:               "bundleName candidate matches over filename",
			bundleSymbolicName: "com.example.mylib",
			bundleName:         "MyLib",
			filenameArtifact:   "something-else",
			want:               "com.example",
		},
		{
			name:               "BSN exactly 6 chars with dot - len > 5 passes",
			bundleSymbolicName: "ab.cde",
			bundleName:         "",
			filenameArtifact:   "cde",
			want:               "ab",
		},
		{
			name:               "candidate same as BSN - no stripping",
			bundleSymbolicName: "org.example",
			bundleName:         "",
			filenameArtifact:   "org.example",
			want:               "org.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseGroupID(tt.bundleSymbolicName, tt.bundleName, tt.filenameArtifact)
			if got != tt.want {
				t.Errorf("parseGroupID(%q, %q, %q) = %q, want %q",
					tt.bundleSymbolicName, tt.bundleName, tt.filenameArtifact, got, tt.want)
			}
		})
	}
}

// ============================================================================
// T-3: resolveManifestPackage tests
// ============================================================================

func TestResolveManifestPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		filenameArtifact string
		filenameVersion  string
		bsn              string
		bundleName       string
		bundleVersion    string
		implTitle        string
		implVersion      string
		wantName         string
		wantVersion      string
	}{
		{
			name:             "full bouncycastle example",
			filenameArtifact: "bcprov-jdk18on",
			filenameVersion:  "1.78.1",
			bsn:              "org.bouncycastle.bcprov-jdk18on",
			bundleName:       "bcprov",
			bundleVersion:    "1.78.1",
			implTitle:        "bcprov",
			implVersion:      "1.78.1",
			wantName:         "org.bouncycastle:bcprov",
			wantVersion:      "1.78.1",
		},
		{
			name:             "version agreement - bundle==impl preferred",
			filenameArtifact: "mylib",
			filenameVersion:  "2.0.0",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "1.5.0",
			implTitle:        "",
			implVersion:      "1.5.0",
			wantName:         "com.example:mylib",
			wantVersion:      "1.5.0",
		},
		{
			name:             "version disagreement - filename preferred",
			filenameArtifact: "mylib",
			filenameVersion:  "2.0.0",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "1.5.0",
			implTitle:        "",
			implVersion:      "1.6.0",
			wantName:         "com.example:mylib",
			wantVersion:      "2.0.0",
		},
		{
			name:             "no filename version - bundle version fallback",
			filenameArtifact: "mylib",
			filenameVersion:  "",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "1.5.0",
			implTitle:        "",
			implVersion:      "",
			wantName:         "com.example:mylib",
			wantVersion:      "1.5.0",
		},
		{
			name:             "no filename version no bundle version - impl version fallback",
			filenameArtifact: "mylib",
			filenameVersion:  "",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "",
			implTitle:        "",
			implVersion:      "3.0.0",
			wantName:         "com.example:mylib",
			wantVersion:      "3.0.0",
		},
		{
			name:             "artifactId priority - bundleName preferred over implTitle",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.my-bundle",
			bundleName:       "My Bundle",
			bundleVersion:    "1.0.0",
			implTitle:        "ImplArt",
			implVersion:      "1.0.0",
			wantName:         "com.example:my-bundle",
			wantVersion:      "1.0.0",
		},
		{
			name:             "artifactId priority - implTitle when no bundleName",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.implart",
			bundleName:       "",
			bundleVersion:    "1.0.0",
			implTitle:        "ImplArt",
			implVersion:      "1.0.0",
			// groupId uses filename-art and bundleName as candidates, not chosen artifactId.
			// BSN doesn't end with ".filename-art", so groupId falls back to full BSN.
			wantName:    "com.example.implart:implart",
			wantVersion: "1.0.0",
		},
		{
			name:             "artifactId priority - filename when no bundleName or implTitle",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.filename-art",
			bundleName:       "",
			bundleVersion:    "1.0.0",
			implTitle:        "",
			implVersion:      "1.0.0",
			wantName:         "com.example:filename-art",
			wantVersion:      "1.0.0",
		},
		{
			name:             "empty BSN - no package emitted",
			filenameArtifact: "mylib",
			filenameVersion:  "1.0.0",
			bsn:              "",
			bundleName:       "",
			bundleVersion:    "",
			implTitle:        "",
			implVersion:      "",
			wantName:         "",
			wantVersion:      "",
		},
		{
			name:             "no version anywhere - still emits package",
			filenameArtifact: "mylib",
			filenameVersion:  "",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "",
			implTitle:        "",
			implVersion:      "",
			wantName:         "com.example:mylib",
			wantVersion:      "",
		},
		{
			name:             "BSN with singleton directive - gets cleaned",
			filenameArtifact: "runtime",
			filenameVersion:  "3.26.0",
			bsn:              "org.eclipse.core.runtime;singleton:=true",
			bundleName:       "",
			bundleVersion:    "3.26.0",
			implTitle:        "",
			implVersion:      "",
			wantName:         "org.eclipse.core:runtime",
			wantVersion:      "3.26.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotName, gotVersion := resolveManifestPackage(
				tt.filenameArtifact, tt.filenameVersion,
				tt.bsn, tt.bundleName, tt.bundleVersion,
				tt.implTitle, tt.implVersion,
			)
			if gotName != tt.wantName {
				t.Errorf("resolveManifestPackage() name = %q, want %q", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("resolveManifestPackage() version = %q, want %q", gotVersion, tt.wantVersion)
			}
		})
	}
}
