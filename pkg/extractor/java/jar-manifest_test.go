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
		// Classifier stripping
		{
			name:           "platform classifier linux-x86_64 stripped",
			filename:       "netty-tcnative-boringssl-static-2.0.61.Final-linux-x86_64.jar",
			wantArtifactID: "netty-tcnative-boringssl-static",
			wantVersion:    "2.0.61.Final",
		},
		{
			name:           "platform classifier linux-aarch_64 stripped",
			filename:       "netty-tcnative-boringssl-static-2.0.61.Final-linux-aarch_64.jar",
			wantArtifactID: "netty-tcnative-boringssl-static",
			wantVersion:    "2.0.61.Final",
		},
		{
			name:           "platform classifier osx-x86_64 stripped",
			filename:       "grpc-netty-1.50.0-osx-x86_64.jar",
			wantArtifactID: "grpc-netty",
			wantVersion:    "1.50.0",
		},
		{
			// Regex splits at first -digit boundary: artifactId="guava", version="31.1-jre-sources".
			// Classifier stripping then removes "-sources", leaving version="31.1-jre".
			name:           "sources classifier stripped",
			filename:       "guava-31.1-jre-sources.jar",
			wantArtifactID: "guava",
			wantVersion:    "31.1-jre",
		},
		{
			name:           "SNAPSHOT qualifier not stripped",
			filename:       "spring-core-5.3.0-SNAPSHOT.jar",
			wantArtifactID: "spring-core",
			wantVersion:    "5.3.0-SNAPSHOT",
		},
		{
			name:           "Final qualifier not stripped",
			filename:       "netty-tcnative-2.0.61.Final.jar",
			wantArtifactID: "netty-tcnative",
			wantVersion:    "2.0.61.Final",
		},
		{
			// artifactId contains a hyphen-digit segment; greedy match finds the
			// rightmost -\d boundary so the split is correct.
			name:           "artifactId with embedded hyphen-digit segment",
			filename:       "log4j-1.2-api-2.17.1.jar",
			wantArtifactID: "log4j-1.2-api",
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
		wantImplVersion   string
		wantAMN           string
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
			wantImplVersion:   "1.78.1",
		},
		{
			name:              "only manifest version",
			manifest:          "Manifest-Version: 1.0\r\n",
			wantBSN:           "",
			wantBundleName:    "",
			wantBundleVersion: "",
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
			wantImplVersion:   "",
		},
		{
			// Per-entry sections follow the blank line that ends the main section.
			// Attributes in those sections must not overwrite main-section values.
			name: "per-entry section ignored after blank line",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Bundle-SymbolicName: org.bouncycastle.bcprov\r\n" +
				"Bundle-Version: 1.78.1\r\n" +
				"\r\n" +
				"Name: com/example/SomeClass.class\r\n" +
				"Bundle-SymbolicName: com.attacker.evil\r\n" +
				"Implementation-Version: 99.0.0\r\n",
			wantBSN:           "org.bouncycastle.bcprov",
			wantBundleName:    "",
			wantBundleVersion: "1.78.1",
			wantImplVersion:   "",
		},
		{
			name: "Automatic-Module-Name extracted",
			manifest: "Manifest-Version: 1.0\r\n" +
				"Bundle-SymbolicName: bcprov\r\n" +
				"Bundle-Name: bcprov\r\n" +
				"Bundle-Version: 1.78.1\r\n" +
				"Automatic-Module-Name: org.bouncycastle.provider\r\n",
			wantBSN:           "bcprov",
			wantBundleName:    "bcprov",
			wantBundleVersion: "1.78.1",
			wantAMN:           "org.bouncycastle.provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			reader := createTestJar(t, tt.manifest)
			mf, err := parseManifestAttributes(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseManifestAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if mf.bundleSymbolicName != tt.wantBSN {
				t.Errorf("BSN = %q, want %q", mf.bundleSymbolicName, tt.wantBSN)
			}
			if mf.bundleName != tt.wantBundleName {
				t.Errorf("BundleName = %q, want %q", mf.bundleName, tt.wantBundleName)
			}
			if mf.bundleVersion != tt.wantBundleVersion {
				t.Errorf("BundleVersion = %q, want %q", mf.bundleVersion, tt.wantBundleVersion)
			}
			if mf.implVersion != tt.wantImplVersion {
				t.Errorf("ImplVersion = %q, want %q", mf.implVersion, tt.wantImplVersion)
			}
			if mf.automaticModuleName != tt.wantAMN {
				t.Errorf("AutomaticModuleName = %q, want %q", mf.automaticModuleName, tt.wantAMN)
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

	mf, err := parseManifestAttributes(reader)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// All should be empty when no MANIFEST.MF exists
	if mf != (manifestAttrs{}) {
		t.Errorf("expected zero manifestAttrs, got %+v", mf)
	}
}

// ============================================================================
// T-2: parseGroupID tests
// ============================================================================

func TestParseGroupId(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		bundleSymbolicName  string
		bundleName          string
		filenameArtifact    string
		automaticModuleName string
		want                string
	}{
		{
			name:               "bouncycastle - filename candidate matches BSN suffix",
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
			name:               "BSN with no dots and no AMN - fallback to BSN",
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
		// AMN fallback cases (BSN has no dots)
		{
			// BouncyCastle: BSN="bcprov" has no dots; AMN="org.bouncycastle.provider"
			// has 3 segments so last-segment stripping gives "org.bouncycastle".
			name:                "AMN last-segment strip when BSN has no dots - bouncycastle",
			bundleSymbolicName:  "bcprov",
			bundleName:          "bcprov",
			filenameArtifact:    "bcprov-jdk15to18",
			automaticModuleName: "org.bouncycastle.provider",
			want:                "org.bouncycastle",
		},
		{
			// AMN "com.mylib" has only 1 dot (2 segments). The dot-prefix heuristic
			// can't match because filenameArtifact differs from AMN's suffix, so it
			// falls through to the last-segment threshold check (requires >= 2 dots).
			// With only 1 dot the strip is skipped and BSN is returned as-is.
			name:                "AMN with 1 dot - below threshold, fallback to BSN",
			bundleSymbolicName:  "mylib",
			bundleName:          "",
			filenameArtifact:    "unrelated-artifact",
			automaticModuleName: "com.mylib",
			want:                "mylib",
		},
		{
			// BSN has dots → AMN path is skipped; BSN dot-prefix is used.
			name:                "BSN with dots - AMN path not taken",
			bundleSymbolicName:  "org.bouncycastle.bcprov-jdk18on",
			bundleName:          "",
			filenameArtifact:    "bcprov-jdk18on",
			automaticModuleName: "org.bouncycastle.provider",
			want:                "org.bouncycastle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseGroupID(tt.bundleSymbolicName, tt.bundleName, tt.filenameArtifact, tt.automaticModuleName)
			if got != tt.want {
				t.Errorf("parseGroupID(%q, %q, %q, %q) = %q, want %q",
					tt.bundleSymbolicName, tt.bundleName, tt.filenameArtifact, tt.automaticModuleName, got, tt.want)
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
		name                string
		filenameArtifact    string
		filenameVersion     string
		bsn                 string
		bundleName          string
		bundleVersion       string
		implVersion         string
		automaticModuleName string
		wantName            string
		wantVersion         string
	}{
		{
			// JAR has BSN with dots: dot-prefix heuristic gives groupId=org.bouncycastle.
			// Bundle-Name "bcprov" is a display name; filename artifact "bcprov-jdk18on"
			// is the correct Maven artifactId and is always preferred.
			name:             "bouncycastle with full BSN - filename artifact preferred over bundle name",
			filenameArtifact: "bcprov-jdk18on",
			filenameVersion:  "1.78.1",
			bsn:              "org.bouncycastle.bcprov-jdk18on",
			bundleName:       "bcprov",
			bundleVersion:    "1.78.1",
			implVersion:      "1.78.1",
			wantName:         "org.bouncycastle:bcprov-jdk18on",
			wantVersion:      "1.78.1",
		},
		{
			// Real bcprov-jdk15to18: BSN="bcprov" (no dots), Bundle-Name="bcprov" (same as BSN),
			// AMN="org.bouncycastle.provider". Expects filename artifact and AMN-derived groupId.
			name:                "bouncycastle jdk15to18 - AMN groupId + filename artifactId",
			filenameArtifact:    "bcprov-jdk15to18",
			filenameVersion:     "1.78.1",
			bsn:                 "bcprov",
			bundleName:          "bcprov",
			bundleVersion:       "1..78.1",
			implVersion:         "1.78.1.0",
			automaticModuleName: "org.bouncycastle.provider",
			wantName:            "org.bouncycastle:bcprov-jdk15to18",
			wantVersion:         "1.78.1",
		},
		{
			name:             "version agreement - bundle==impl preferred",
			filenameArtifact: "mylib",
			filenameVersion:  "2.0.0",
			bsn:              "com.example.mylib",
			bundleName:       "",
			bundleVersion:    "1.5.0",
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
			implVersion:      "3.0.0",
			wantName:         "com.example:mylib",
			wantVersion:      "3.0.0",
		},
		{
			// Bundle-Name and Implementation-Title are display names; filename artifact
			// is always used as the Maven artifactId regardless.
			name:             "filename artifact used despite bundle name and impl title being present",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.filename-art",
			bundleName:       "My Bundle",
			bundleVersion:    "1.0.0",
			implVersion:      "1.0.0",
			wantName:         "com.example:filename-art",
			wantVersion:      "1.0.0",
		},
		{
			name:             "filename artifact used when no bundle name or impl title",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.filename-art",
			bundleName:       "",
			bundleVersion:    "1.0.0",
			implVersion:      "1.0.0",
			wantName:         "com.example:filename-art",
			wantVersion:      "1.0.0",
		},
		{
			name:             "artifactId priority - filename when no bundleName or implTitle",
			filenameArtifact: "filename-art",
			filenameVersion:  "1.0.0",
			bsn:              "com.example.filename-art",
			bundleName:       "",
			bundleVersion:    "1.0.0",
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
				tt.implVersion,
				tt.automaticModuleName,
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
