package java

import (
	"archive/zip"
	"bufio"
	"fmt"
	"os"
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
)

// JarPomPropertiesExtractor extracts Maven artifact information from
// pom.properties files embedded inside JAR (ZIP) archives.
type JarPomPropertiesExtractor struct{}

func (e JarPomPropertiesExtractor) ShouldExtract(path string) bool {
	return filepath.Ext(path) == ".jar"
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

	packages := make([]extractor.PackageDetails, 0, len(zipReader.File))

	for _, entry := range zipReader.File {
		if !strings.HasPrefix(entry.Name, pomPropertiesPrefix) || !strings.HasSuffix(entry.Name, pomPropertiesSuffix) {
			continue
		}

		groupID, artifactID, version, parseErr := parsePomProperties(entry)
		if parseErr != nil {
			context.Reporter.Warnf("Failed to read pom.properties in %s: %s: %v\n", f.Path(), entry.Name, parseErr)
			continue
		}

		if groupID == "" || artifactID == "" || version == "" {
			context.Reporter.Warnf("Skipping incomplete pom.properties in %s: %s (groupId=%q, artifactId=%q, version=%q)\n",
				f.Path(), entry.Name, groupID, artifactID, version)

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
		packages = extractFromManifest(f.Path(), zipReader, packages)
	}

	return packages, nil
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
