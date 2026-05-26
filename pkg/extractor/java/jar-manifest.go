package java

import (
	"archive/zip"
	"bufio"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// jarFilenameRegex matches Maven-convention JAR filenames: artifactId-version.jar
// The version must start with a digit. The artifactId uses a greedy match so that
// the split occurs at the LAST hyphen-digit boundary, not the first. This correctly
// handles artifactIds that themselves contain a hyphen-digit segment, e.g.
// log4j-1.2-api-2.17.1.jar → artifactId="log4j-1.2-api", version="2.17.1".
var jarFilenameRegex = cachedregexp.MustCompile(`^(.+)-(\d.*)\.jar$`)

// jarClassifierRegex matches known Maven classifier suffixes appended at the end of a
// version string in a JAR filename. Classifiers are either OS/architecture identifiers
// (linux, windows, osx, …) optionally followed by an arch token, or well-known
// descriptor strings (sources, javadoc, native, …).
//
// Version qualifiers such as -SNAPSHOT, -Final, -RC1 are intentionally excluded so
// they are never stripped.
var jarClassifierRegex = cachedregexp.MustCompile(
	`-(?:linux|windows|osx|macos|darwin|freebsd|sunos|solaris|aix)(?:[_-][a-z0-9_]+)*$` +
		`|-(?:sources|javadoc|tests|native|all|uber|shaded|assembly|no_aop)$`,
)

// parseJarFilename extracts artifactId and version from a JAR filename following
// Maven naming conventions. If the version portion contains a known classifier suffix
// (e.g. "-linux-x86_64", "-sources"), the classifier is stripped so that only the
// canonical Maven version is returned. Returns empty strings if the filename doesn't
// match the expected pattern.
func parseJarFilename(filename string) (artifactID, version string) {
	matches := jarFilenameRegex.FindStringSubmatch(filename)
	if matches == nil {
		return "", ""
	}

	return matches[1], jarClassifierRegex.ReplaceAllString(matches[2], "")
}

// cleanBundleSymbolicName strips OSGi directives (everything after the first ';')
// from a Bundle-SymbolicName value and trims whitespace.
func cleanBundleSymbolicName(raw string) string {
	raw = strings.TrimSpace(raw)
	if idx := strings.IndexByte(raw, ';'); idx >= 0 {
		raw = strings.TrimSpace(raw[:idx])
	}

	return raw
}

// cleanName normalizes a manifest attribute value for use as an artifactId:
// lowercases, replaces spaces with hyphens, removes non-alphanumeric chars
// (except hyphens, underscores, dots).
func cleanName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	raw = strings.ToLower(raw)
	raw = strings.ReplaceAll(raw, " ", "-")

	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		}
	}

	return b.String()
}

// manifestAttrs holds the MANIFEST.MF attributes relevant to fallback package inference.
// Raw attribute values are stored (not cleaned) so callers can apply appropriate cleaning.
type manifestAttrs struct {
	bundleSymbolicName  string
	bundleName          string
	bundleVersion       string
	implVersion         string
	automaticModuleName string
}

// parseManifestAttributes reads META-INF/MANIFEST.MF from a zip archive and
// returns the attributes relevant to fallback package inference.
// Parsing stops at the first blank line, which ends the main section; per-entry
// sections that follow must not overwrite main-section values.
func parseManifestAttributes(zipReader *zip.Reader) (manifestAttrs, error) {
	var manifestEntry *zip.File
	for _, entry := range zipReader.File {
		if entry.Name == "META-INF/MANIFEST.MF" {
			manifestEntry = entry

			break
		}
	}

	if manifestEntry == nil {
		return manifestAttrs{}, nil
	}

	rc, err := manifestEntry.Open()
	if err != nil {
		return manifestAttrs{}, err
	}
	defer rc.Close()

	// Parse MANIFEST.MF format: key-value pairs with continuation lines
	// (lines starting with a space are appended to the previous value).
	attrs := make(map[string]string)

	var currentKey string

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := scanner.Text()

		// A blank line ends the main section of the manifest.
		// Per-entry sections follow and must not overwrite main-section attributes.
		if line == "" {
			break
		}

		// Continuation line: starts with a single space
		if strings.HasPrefix(line, " ") && currentKey != "" {
			attrs[currentKey] += strings.TrimPrefix(line, " ")

			continue
		}

		key, value, found := strings.Cut(line, ": ")
		if !found {
			currentKey = ""

			continue
		}

		currentKey = key
		attrs[currentKey] = value
	}

	if err := scanner.Err(); err != nil {
		return manifestAttrs{}, err
	}

	return manifestAttrs{
		bundleSymbolicName:  attrs["Bundle-SymbolicName"],
		bundleName:          attrs["Bundle-Name"],
		bundleVersion:       attrs["Bundle-Version"],
		implVersion:         attrs["Implementation-Version"],
		automaticModuleName: attrs["Automatic-Module-Name"],
	}, nil
}

// parseGroupID infers a Maven groupId from MANIFEST.MF attributes using the
// dot-prefix heuristic from the Java Tracer's Dependency.java guessFallbackNoPom.
//
// Primary algorithm (BSN-based):
//  1. Build candidate names: [filenameArtifact, cleanName(bundleName)]
//  2. For each candidate, check if BSN ends with "." + candidate AND BSN contains "." AND len(BSN) > 5
//  3. If match: groupId = BSN prefix (BSN minus "." + candidate)
//
// Fallback when BSN has no dots (poor OSGi metadata, e.g. Bundle-SymbolicName: "bcprov"):
//  1. Apply the same dot-prefix heuristic to Automatic-Module-Name
//  2. If no candidate matches, strip the last dot-segment of AMN as a best-effort groupId
//     (requires AMN to have at least 2 dots for confidence)
//
// Final fallback: BSN as-is.
func parseGroupID(bundleSymbolicName, bundleName, filenameArtifact, automaticModuleName string) string {
	if bundleSymbolicName == "" {
		return ""
	}

	// Build candidate list: filename artifact first, then cleaned bundle name
	var candidates []string
	if filenameArtifact != "" {
		candidates = append(candidates, filenameArtifact)
	}

	if cleanedBundleName := cleanName(bundleName); cleanedBundleName != "" {
		candidates = append(candidates, cleanedBundleName)
	}

	// Primary: dot-prefix heuristic on BSN
	for _, candidate := range candidates {
		suffix := "." + candidate
		if strings.HasSuffix(bundleSymbolicName, suffix) &&
			strings.Contains(bundleSymbolicName, ".") &&
			len(bundleSymbolicName) > 5 {
			return bundleSymbolicName[:len(bundleSymbolicName)-len(suffix)]
		}
	}

	// BSN-based inference failed. When BSN has no dots (e.g. "bcprov"), it carries
	// no package hierarchy. Try Automatic-Module-Name as a more reliable source.
	if !strings.Contains(bundleSymbolicName, ".") && automaticModuleName != "" {
		// Dot-prefix heuristic on AMN
		for _, candidate := range candidates {
			suffix := "." + candidate
			if strings.HasSuffix(automaticModuleName, suffix) &&
				strings.Contains(automaticModuleName, ".") &&
				len(automaticModuleName) > 5 {
				return automaticModuleName[:len(automaticModuleName)-len(suffix)]
			}
		}

		// No candidate matched. Strip the last dot-segment of AMN as a best-effort
		// groupId (e.g. "org.bouncycastle.provider" → "org.bouncycastle").
		// Require at least 2 dots (3 segments) to avoid over-truncating short names.
		if strings.Count(automaticModuleName, ".") >= 2 {
			if idx := strings.LastIndex(automaticModuleName, "."); idx > 0 {
				return automaticModuleName[:idx]
			}
		}
	}

	// No candidate matched; use BSN as-is
	return bundleSymbolicName
}

// resolveManifestPackage determines the final package name and version from
// MANIFEST.MF attributes and filename-derived values.
//
// ArtifactId: always the filename-derived artifact ID.
// Bundle-Name and Implementation-Title are OSGi/JAR display names and frequently
// do not match the Maven artifactId (e.g. Bundle-Name "bcprov" vs filename artifact
// "bcprov-jdk18on"). The filename is the authoritative source for the Maven coordinate.
//
// Version priority: bundleVersion==implVersion agreement > filenameVersion > bundleVersion > implVersion > ""
//
// Implementation-Title is intentionally excluded: it is an OSGi/JAR display name
// and is not reliably set to the Maven artifactId.
//
// Returns empty name if groupId or artifactId cannot be determined.
func resolveManifestPackage(filenameArtifact, filenameVersion, rawBSN, bundleName, bundleVersion, implVersion, automaticModuleName string) (name, version string) {
	bsn := cleanBundleSymbolicName(rawBSN)
	if bsn == "" {
		return "", ""
	}

	// artifactId comes from the filename: it is the most reliable source of the Maven
	// artifact ID. Bundle-Name / Implementation-Title are display names only.
	artifactID := filenameArtifact
	if artifactID == "" {
		return "", ""
	}

	// Resolve version by priority
	if bundleVersion != "" && bundleVersion == implVersion {
		// High confidence: both sources agree
		version = bundleVersion
	} else if filenameVersion != "" {
		version = filenameVersion
	} else if bundleVersion != "" {
		version = bundleVersion
	} else {
		version = implVersion
	}

	// Resolve groupId using filename artifact and bundle name as candidates
	// (not the resolved artifactId — groupId inference has its own candidate list)
	groupID := parseGroupID(bsn, bundleName, filenameArtifact, automaticModuleName)
	if groupID == "" {
		return "", ""
	}

	return groupID + ":" + artifactID, version
}

// extractFromManifest attempts to infer a Maven package from the JAR's
// MANIFEST.MF attributes and filename. This is the fallback path used when
// no pom.properties are found inside the JAR.
func extractFromManifest(jarPath string, zipReader *zip.Reader, packages []extractor.PackageDetails) []extractor.PackageDetails {
	filenameArtifact, filenameVersion := parseJarFilename(filepath.Base(jarPath))
	if filenameArtifact == "" {
		// Filename doesn't match Maven convention; cannot infer package
		return packages
	}

	mf, err := parseManifestAttributes(zipReader)
	if err != nil {
		// Silently skip on parse error — this is a best-effort fallback
		return packages
	}

	name, version := resolveManifestPackage(
		filenameArtifact, filenameVersion,
		mf.bundleSymbolicName, mf.bundleName, mf.bundleVersion,
		mf.implVersion,
		mf.automaticModuleName,
	)

	if name == "" {
		return packages
	}

	return append(packages, extractor.PackageDetails{
		Name:           name,
		Version:        version,
		PackageManager: jarPomPropertiesPackageManager,
		Ecosystem:      models.EcosystemMaven,
		Opaque:         true,
		IsDirect:       true,
	})
}
