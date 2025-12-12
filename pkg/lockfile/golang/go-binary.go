package golang

import (
	"bytes"
	"debug/buildinfo"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	goBinaryPackageManager      = models.Golang
	goBinaryOfficiallySupported = false
)

type GoBinaryExtractor struct{}

func (e GoBinaryExtractor) ShouldExtract(path string) bool {
	if path == "" {
		return false
	}

	if strings.HasSuffix(path, string(filepath.Separator)) { // Don't extract directories
		return false
	}

	if filepath.Ext(path) != ".exe" && filepath.Ext(path) != "" {
		// Assume if a file has an extension (that's not exe), it is not a go binary
		// This also filters out hidden files on Unix
		// This is a heuristic to improve performance and can result in false negatives
		// TODO(another-rex): When we have access to the full FS interface, we can open and check
		// magic bytes to be more accurate
		return false
	}

	// Any other path can be a go binary
	return true
}

func (e GoBinaryExtractor) IsOfficiallySupported() bool {
	return goBinaryOfficiallySupported
}

func (e GoBinaryExtractor) PackageManager() models.PackageManager {
	return goBinaryPackageManager
}

func (e GoBinaryExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var readerAt io.ReaderAt
	if fileWithReaderAt, ok := f.(io.ReaderAt); ok {
		readerAt = fileWithReaderAt
	} else {
		buf := bytes.NewBuffer([]byte{})
		_, err := io.Copy(buf, f)
		if err != nil {
			return []lockfile.PackageDetails{}, err
		}
		readerAt = bytes.NewReader(buf.Bytes())
	}

	info, err := buildinfo.Read(readerAt)
	if err != nil {
		return []lockfile.PackageDetails{}, lockfile.ErrIncompatibleFileFormat
	}

	pkgs := make([]lockfile.PackageDetails, 0, len(info.Deps)+1)
	pkgs = append(pkgs, lockfile.PackageDetails{
		Name:           "stdlib",
		Version:        strings.TrimPrefix(info.GoVersion, "go"),
		Ecosystem:      models.EcosystemGo,
		PackageManager: goBinaryPackageManager,
	})

	for _, dep := range info.Deps {
		if dep.Replace != nil { // Use the replaced dep if it has been replaced
			dep = dep.Replace
		}
		pkgs = append(pkgs, lockfile.PackageDetails{
			Name:           dep.Path,
			Version:        strings.TrimPrefix(dep.Version, "v"),
			Ecosystem:      models.EcosystemGo,
			PackageManager: goBinaryPackageManager,
		})
	}

	return pkgs, nil
}

var _ lockfile.Extractor = GoBinaryExtractor{}

var GoBinaryExtractorInstance = GoBinaryExtractor{}

func ParseGoBinaryLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, GoBinaryExtractor{})
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.GolangBinaryFilePath, GoBinaryExtractorInstance)
}
