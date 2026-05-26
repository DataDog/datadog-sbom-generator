package extractor

import (
	"io"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// DepFile is an abstraction for a file that has been opened for extraction,
// and that knows how to open other DepFiles relative to itself.
type DepFile interface {
	io.Reader
	io.Closer
	// Open opens an DepFile based on the path of the
	// current DepFile if the provided path is relative.
	//
	// If the path is an absolute path, then it is opened absolutely.
	Open(path string) (DepFile, error)

	Path() string
}

type Extractor interface {
	// ShouldExtract checks if the Extractor should be used for the given path.
	ShouldExtract(path string) bool
	Extract(f DepFile, context ScanContext) ([]PackageDetails, error)
	// IsOfficiallySupported returns true if the extractor is officially supported by Datadog SCA E2E
	IsOfficiallySupported() bool
	PackageManager() models.PackageManager
}

type WithMatcher struct {
	Matchers []Matcher
}

type ExtractorWithMatcher interface {
	Extractor
	GetMatchers() []Matcher
}

type ArtifactExtractor interface {
	GetArtifact(f DepFile, context ScanContext) (*models.ScannedArtifact, error)
}

// ManifestExtractor is an optional interface for extractors that parse manifest
// files directly (e.g. pyproject.toml) when no lock file is present.
// These extractors are opt-in and not included in the default parser set.
type ManifestExtractor interface {
	Extractor
	IsManifestParser() bool
}

func (e WithMatcher) GetMatchers() []Matcher {
	return e.Matchers
}

// A LocalFile represents a file that exists on the local filesystem.
type LocalFile struct {
	io.Reader
	io.Closer

	path string
}

func (f LocalFile) Open(path string) (DepFile, error) {
	if filepath.IsAbs(path) {
		return OpenLocalDepFile(path)
	}

	return OpenLocalDepFile(filepath.Join(filepath.Dir(f.path), path))
}

func (f LocalFile) Path() string { return f.path }

func OpenLocalDepFile(path string) (DepFile, error) {
	r, err := os.Open(path)

	if err != nil {
		return LocalFile{}, err
	}

	// Very unlikely to have Abs return an error if the file opens correctly
	path, _ = filepath.Abs(path)

	// We apply a decoder on it to avoid issues with utf-16
	var transformer = unicode.BOMOverride(encoding.Nop.NewDecoder())
	decodedReader := transform.NewReader(r, transformer)

	return LocalFile{decodedReader, r, path}, nil
}

var _ DepFile = LocalFile{}
var _ DepFile = LocalFile{}

func ExtractFromFile(pathToLockfile string, extractor Extractor) ([]PackageDetails, error) {
	// Extracting directly a single file is used in tests environments.
	// Thus, we do not require a complete context to pass a context to it.
	r, err := reporter.New("cyclonedx-1-5", os.Stdout, os.Stderr, reporter.ErrorLevel, true)
	context := ScanContext{Reporter: r}

	if err != nil {
		return []PackageDetails{}, err
	}

	return ExtractFromFileWithContext(pathToLockfile, extractor, context)
}

func ExtractFromFileWithContext(pathToLockfile string, extractor Extractor, context ScanContext) ([]PackageDetails, error) {
	f, err := OpenLocalDepFile(pathToLockfile)

	if err != nil {
		return []PackageDetails{}, err
	}

	defer f.Close()

	packages, err := extractor.Extract(f, context)
	if err != nil {
		return []PackageDetails{}, err
	}

	// Match extracted packages with source file to enrich their details
	if e, ok := extractor.(ExtractorWithMatcher); ok {
		if matchers := e.GetMatchers(); len(matchers) > 0 {
			for _, matcher := range matchers {
				matchError := matchWithFile(f, packages, matcher, context)
				if matchError != nil {
					// _, _ = fmt.Fprintf(os.Stderr, "there was an error matching the source file %s: %s\n", pathToLockfile, matchError.Error())
					context.Reporter.Errorf("there was an error matching the source file %s: %s\n", pathToLockfile, matchError.Error())
				}
			}
		}
	}

	return packages, nil
}
