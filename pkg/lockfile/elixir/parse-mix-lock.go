package elixir

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

const (
	mixPackageManager      = models.Hex
	mixOfficiallySupported = false
)

type MixLockExtractor struct{}

func (e MixLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.HexFilePath.String()
}

func (e MixLockExtractor) IsOfficiallySupported() bool {
	return mixOfficiallySupported
}

func (e MixLockExtractor) PackageManager() models.PackageManager {
	return mixPackageManager
}

func (e MixLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	re := cachedregexp.MustCompile(`^ +"(\w+)": \{.+,$`)

	scanner := bufio.NewScanner(f)

	var packages []lockfile.PackageDetails

	for scanner.Scan() {
		line := scanner.Text()

		match := re.FindStringSubmatch(line)

		if match == nil {
			continue
		}

		// we only care about the third and fourth "rows" which are both strings,
		// so we can safely split the line as if it's a set of comma-separated fields
		// even though that'll actually poorly represent nested arrays & objects
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ','
		})

		if len(fields) < 4 {
			context.Reporter.Errorf(
				"Found less than four fields when parsing a line that looks like a dependency in a mix.lock - please report this!\n",
			)

			continue
		}

		name := match[1]
		version := strings.TrimSpace(fields[2])
		commit := strings.TrimSpace(fields[3])

		version = strings.TrimSuffix(strings.TrimPrefix(version, `"`), `"`)
		commit = strings.TrimSuffix(strings.TrimPrefix(commit, `"`), `"`)

		if strings.HasSuffix(fields[0], ":git") {
			commit = version
			version = ""
		}

		packages = append(packages, lockfile.PackageDetails{
			Name:           name,
			Version:        version,
			PackageManager: mixPackageManager,
			Ecosystem:      models.EcosystemHex,
			Commit:         commit,
		})
	}

	if err := scanner.Err(); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("error while scanning %s: %w", f.Path(), err)
	}

	return packages, nil
}

var _ lockfile.Extractor = MixLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.HexFilePath, MixLockExtractor{})
}

func ParseMixLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, MixLockExtractor{})
}
