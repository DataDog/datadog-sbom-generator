package java

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	jarPomPropertiesPackageManager      = models.Maven
	jarPomPropertiesOfficiallySupported = false

	pomPropertiesPrefix = "META-INF/maven/"
	pomPropertiesSuffix = "/pom.properties"

	// maxArchiveDepth bounds archive nesting (EAR > WAR > fat JAR > JAR needs 3).
	maxArchiveDepth = 5
)

// maxNestedArchiveSize bounds the bytes read into memory per nested archive.
// It is a variable so tests can lower it.
var maxNestedArchiveSize uint64 = 256 << 20

// maxNestedArchiveBudget bounds the bytes decompressed across all nested
// archives of one top-level file. It is a variable so tests can lower it.
var maxNestedArchiveBudget = 4 * maxNestedArchiveSize

// JarPomPropertiesExtractor extracts Maven artifact information from
// pom.properties files embedded inside JAR (ZIP) archives. WAR and EAR archives
// are treated as containers: they are not reported themselves, but the JARs
// they contain are. Nested archives (jar-in-jar, war-in-ear) are walked
// recursively.
type JarPomPropertiesExtractor struct{}

func (e JarPomPropertiesExtractor) ShouldExtract(path string) bool {
	return isArchiveName(filepath.Base(path)) && !strings.HasSuffix(path, "/")
}

func (e JarPomPropertiesExtractor) IsOfficiallySupported() bool {
	return jarPomPropertiesOfficiallySupported
}

func (e JarPomPropertiesExtractor) PackageManager() models.PackageManager {
	return jarPomPropertiesPackageManager
}

func (e JarPomPropertiesExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	// Open the file directly by path to get an io.ReaderAt for archive/zip.
	// The DepFile reader wraps files with a BOM decoder which is not suitable
	// for binary archive data, and archive/zip.NewReader requires io.ReaderAt.
	file, err := os.Open(f.Path())
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not open %s: %w", f.Path(), err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not stat %s: %w", f.Path(), err)
	}

	zipReader, err := zip.NewReader(file, stat.Size())
	if err != nil {
		return []extractor.PackageDetails{}, extractor.ErrIncompatibleFileFormat
	}

	budget := maxNestedArchiveBudget

	return extractArchive(f.Path(), filepath.Base(f.Path()), zipReader, 0, &budget, context), nil
}

// extractArchive walks a JAR, WAR or EAR archive. JARs are reported as packages
// (from their root pom.properties or, as fallback, MANIFEST.MF + filename).
// WARs and EARs are containers only. Every nested archive entry is walked
// recursively, up to maxArchiveDepth levels. budget is the number of bytes
// that may still be decompressed across the whole traversal.
func extractArchive(displayPath, name string, zipReader *zip.Reader, depth int, budget *uint64, context extractor.ScanContext) []extractor.PackageDetails {
	var packages []extractor.PackageDetails
	if path.Ext(name) == ".jar" {
		packages = extractJarPackages(displayPath, name, zipReader, context)
	}

	for _, entry := range zipReader.File {
		if entry.FileInfo().IsDir() || !isArchiveName(entry.Name) {
			continue
		}

		nestedPath := displayPath + "!/" + entry.Name
		if depth+1 > maxArchiveDepth {
			context.Reporter.Warnf("Skipping nested archive %s: maximum nesting depth %d reached\n", nestedPath, maxArchiveDepth)
			continue
		}

		nested, err := openNestedArchive(entry, budget)
		if err != nil {
			context.Reporter.Warnf("Skipping nested archive %s: %v\n", nestedPath, err)
			continue
		}

		packages = append(packages, extractArchive(nestedPath, path.Base(entry.Name), nested, depth+1, budget, context)...)
	}

	if packages == nil {
		return []extractor.PackageDetails{}
	}

	return packages
}

func isArchiveName(name string) bool {
	switch path.Ext(name) {
	case ".jar", ".war", ".ear":
		return true
	}

	return false
}

// openNestedArchive reads a nested archive entry into memory (bounded by
// maxNestedArchiveSize and the remaining traversal budget) and opens it as a
// zip. Bytes read are charged to the budget.
func openNestedArchive(entry *zip.File, budget *uint64) (*zip.Reader, error) {
	if entry.UncompressedSize64 > maxNestedArchiveSize {
		return nil, fmt.Errorf("size %d exceeds limit of %d bytes", entry.UncompressedSize64, maxNestedArchiveSize)
	}
	if entry.UncompressedSize64 > *budget {
		return nil, fmt.Errorf("nested archive budget exhausted (%d bytes left)", *budget)
	}
	limit := min(maxNestedArchiveSize, *budget)

	rc, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	buf, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1)) //nolint:gosec // limit is far below math.MaxInt64
	*budget -= min(uint64(len(buf)), *budget)
	if err != nil {
		return nil, err
	}
	if uint64(len(buf)) > limit {
		if limit < maxNestedArchiveSize {
			return nil, errors.New("nested archive budget exhausted")
		}

		return nil, fmt.Errorf("size exceeds limit of %d bytes", maxNestedArchiveSize)
	}

	return zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
}

// extractJarPackages reports the packages declared by the root pom.properties
// files of a single JAR, falling back to MANIFEST.MF + filename.
func extractJarPackages(displayPath, name string, zipReader *zip.Reader, context extractor.ScanContext) []extractor.PackageDetails {
	packages := make([]extractor.PackageDetails, 0)

	for _, entry := range zipReader.File {
		if !strings.HasPrefix(entry.Name, pomPropertiesPrefix) || !strings.HasSuffix(entry.Name, pomPropertiesSuffix) {
			continue
		}

		groupID, artifactID, version, parseErr := parsePomProperties(entry)
		if parseErr != nil {
			context.Reporter.Warnf("Failed to read pom.properties in %s: %s: %v\n", displayPath, entry.Name, parseErr)
			continue
		}

		if groupID == "" || artifactID == "" || version == "" {
			context.Reporter.Warnf("Skipping incomplete pom.properties in %s: %s (groupId=%q, artifactId=%q, version=%q)\n",
				displayPath, entry.Name, groupID, artifactID, version)

			continue
		}

		packages = append(packages, extractor.PackageDetails{
			Name:           groupID + ":" + artifactID,
			Version:        version,
			PackageManager: jarPomPropertiesPackageManager,
			Ecosystem:      models.EcosystemMaven,
			Opaque:         true,
			IsDirect:       true,
		})
	}

	// Fallback: if no pom.properties found, try to infer from MANIFEST.MF + filename
	if len(packages) == 0 {
		packages = extractFromManifest(name, zipReader, packages)
	}

	return packages
}

// parsePomProperties reads a pom.properties file from a ZIP entry and extracts
// the groupId, artifactId, and version values. The format is standard Java
// properties: key=value lines with # or ! comment prefixes.
func parsePomProperties(entry *zip.File) (groupID, artifactID, version string, err error) {
	rc, err := entry.Open()
	if err != nil {
		return "", "", "", err
	}
	defer rc.Close()

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "groupId":
			groupID = value
		case "artifactId":
			artifactID = value
		case "version":
			version = value
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}

	return groupID, artifactID, version, nil
}

var _ extractor.Extractor = JarPomPropertiesExtractor{}

// ParseJarPomProperties is a convenience function for extracting Maven artifacts
// from a JAR file's embedded pom.properties.
func ParseJarPomProperties(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, JarPomPropertiesExtractor{})
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.JarFilePath, JarPomPropertiesExtractor{})
}
