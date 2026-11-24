package extractor

import (
	"bytes"
	"errors"
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

// lazyBOMReader avoids allocating transform.NewReader's 8KB internal buffers
// for the vast majority of files that do not start with a UTF-8/UTF-16 BOM.
type lazyBOMReader struct {
	src      io.Reader
	probed   bool
	fallback io.Reader // set only if a UTF-16 BOM is detected
	buf      [3]byte
	bufPos   int
	bufLen   int
	eof      bool
}

func (l *lazyBOMReader) Read(p []byte) (int, error) {
	if !l.probed {
		l.probed = true
		n, err := io.ReadFull(l.src, l.buf[:])
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, err
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			l.eof = true
		}

		// UTF-16 BE/LE BOM: delegate to unicode.BOMOverride decoder
		if n >= 2 && ((l.buf[0] == 0xFE && l.buf[1] == 0xFF) || (l.buf[0] == 0xFF && l.buf[1] == 0xFE)) {
			transformer := unicode.BOMOverride(encoding.Nop.NewDecoder())
			combined := io.MultiReader(bytes.NewReader(l.buf[:n]), l.src)
			l.fallback = transform.NewReader(combined, transformer)
		} else if n == 3 && l.buf[0] == 0xEF && l.buf[1] == 0xBB && l.buf[2] == 0xBF {
			// UTF-8 BOM: strip the 3 BOM bytes and stream directly from src
			l.bufLen = 0
		} else {
			// No BOM: serve peeked bytes then stream directly from src
			l.bufLen = n
		}
	}

	if l.fallback != nil {
		return l.fallback.Read(p)
	}

	if l.bufPos < l.bufLen {
		n := copy(p, l.buf[l.bufPos:l.bufLen])
		l.bufPos += n
		if l.bufPos == l.bufLen && l.eof {
			return n, io.EOF
		}

		return n, nil
	}

	if l.eof {
		return 0, io.EOF
	}

	return l.src.Read(p)
}

func OpenLocalDepFile(path string) (DepFile, error) {
	r, err := os.Open(path)

	if err != nil {
		return LocalFile{}, err
	}

	// Very unlikely to have Abs return an error if the file opens correctly
	path, _ = filepath.Abs(path)

	return LocalFile{&lazyBOMReader{src: r}, r, path}, nil
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
