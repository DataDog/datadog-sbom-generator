package java

import (
	"archive/zip"
	"bufio"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// jarFilenameRegex matches Maven-convention JAR filenames: artifactId-version.jar
// The version must start with a digit. The artifactId is the minimal non-greedy match,
// and the version captures everything after the first hyphen-digit boundary through .jar.
var jarFilenameRegex = cachedregexp.MustCompile(`^(.+?)-(\d.*)\.jar$`)

// parseJarFilename extracts artifactId and version from a JAR filename following
// Maven naming conventions. Returns empty strings if the filename doesn't match.
func parseJarFilename(filename string) (artifactID, version string) {
	matches := jarFilenameRegex.FindStringSubmatch(filename)
	if matches == nil {
		return "", ""
	}

	return matches[1], matches[2]
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

// parseManifestAttributes reads META-INF/MANIFEST.MF from a zip archive and
// extracts the five relevant attributes for fallback package inference.
// Returns raw attribute values (not cleaned) so callers can apply appropriate cleaning.
func parseManifestAttributes(zipReader *zip.Reader) (bundleSymbolicName, bundleName, bundleVersion, implTitle, implVersion string, err error) {
	var manifestEntry *zip.File
	for _, entry := range zipReader.File {
		if entry.Name == "META-INF/MANIFEST.MF" {
			manifestEntry = entry

			break
		}
	}

	if manifestEntry == nil {
		return "", "", "", "", "", nil
	}

	rc, err := manifestEntry.Open()
	if err != nil {
		return "", "", "", "", "", err
	}
	defer rc.Close()

	// Parse MANIFEST.MF format: key-value pairs with continuation lines
	// (lines starting with a space are appended to the previous value).
	attrs := make(map[string]string)

	var currentKey string

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := scanner.Text()

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
		return "", "", "", "", "", err
	}

	return attrs["Bundle-SymbolicName"],
		attrs["Bundle-Name"],
		attrs["Bundle-Version"],
		attrs["Implementation-Title"],
		attrs["Implementation-Version"],
		nil
}

// parseGroupID infers a Maven groupId from MANIFEST.MF attributes using the
// dot-prefix heuristic from the Java Tracer's Dependency.java guessFallbackNoPom.
//
// Algorithm:
//  1. Build candidate names: [filenameArtifact, cleanName(bundleName)]
//  2. For each candidate, check if BSN ends with "." + candidate AND BSN contains "." AND len(BSN) > 5
//  3. If match: groupId = BSN prefix (BSN minus "." + candidate)
//  4. If no match: groupId = BSN (fallback)
func parseGroupID(bundleSymbolicName, bundleName, filenameArtifact string) string {
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

	for _, candidate := range candidates {
		suffix := "." + candidate
		if strings.HasSuffix(bundleSymbolicName, suffix) &&
			strings.Contains(bundleSymbolicName, ".") &&
			len(bundleSymbolicName) > 5 {
			return bundleSymbolicName[:len(bundleSymbolicName)-len(suffix)]
		}
	}

	// No candidate matched; use BSN as-is
	return bundleSymbolicName
}

// resolveManifestPackage determines the final package name and version from
// MANIFEST.MF attributes and filename-derived values, following the priority
// chains from the Java Tracer's Dependency.java.
//
// ArtifactId priority: cleanName(bundleName) > cleanName(implTitle) > filenameArtifact
// Version priority: bundleVersion==implVersion agreement > filenameVersion > bundleVersion > implVersion > ""
//
// Returns empty name if groupId or artifactId cannot be determined.
func resolveManifestPackage(filenameArtifact, filenameVersion, rawBSN, bundleName, bundleVersion, implTitle, implVersion string) (name, version string) {
	bsn := cleanBundleSymbolicName(rawBSN)
	if bsn == "" {
		return "", ""
	}

	// Resolve artifactId by priority
	var artifactID string

	switch {
	case cleanName(bundleName) != "":
		artifactID = cleanName(bundleName)
	case cleanName(implTitle) != "":
		artifactID = cleanName(implTitle)
	default:
		artifactID = filenameArtifact
	}

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
	groupID := parseGroupID(bsn, bundleName, filenameArtifact)
	if groupID == "" {
		return "", ""
	}

	return groupID + ":" + artifactID, version
}

// extractFromManifest attempts to infer a Maven package from the JAR's
// MANIFEST.MF attributes and filename. This is the fallback path used when
// no pom.properties are found inside the JAR.
func extractFromManifest(jarPath string, zipReader *zip.Reader, packages []lockfile.PackageDetails) []lockfile.PackageDetails {
	filenameArtifact, filenameVersion := parseJarFilename(filepath.Base(jarPath))
	if filenameArtifact == "" {
		// Filename doesn't match Maven convention; cannot infer package
		return packages
	}

	bsn, bundleName, bundleVersion, implTitle, implVersion, err := parseManifestAttributes(zipReader)
	if err != nil {
		// Silently skip on parse error — this is a best-effort fallback
		return packages
	}

	name, version := resolveManifestPackage(
		filenameArtifact, filenameVersion,
		bsn, bundleName, bundleVersion,
		implTitle, implVersion,
	)

	if name == "" {
		return packages
	}

	return append(packages, lockfile.PackageDetails{
		Name:           name,
		Version:        version,
		PackageManager: jarPomPropertiesPackageManager,
		Ecosystem:      models.EcosystemMaven,
		Opaque:         true,
		IsDirect:       true,
	})
}
