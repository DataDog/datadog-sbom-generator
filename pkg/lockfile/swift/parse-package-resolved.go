package swift

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// scpStyleRegexp matches scp-style SSH URLs like git@github.com:org/repo.git
var scpStyleRegexp = cachedregexp.MustCompile(`^[^@]+@([^:]+):(.+)$`)

// PackageResolvedExtractor extracts dependencies from Swift Package.resolved files (v1, v2, v3).
type PackageResolvedExtractor struct {
	lockfile.WithMatcher
}

func (e PackageResolvedExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.SwiftFilePath.String()
}

func (e PackageResolvedExtractor) IsOfficiallySupported() bool {
	return swiftOfficiallySupported
}

func (e PackageResolvedExtractor) PackageManager() models.PackageManager {
	return swiftPackageManager
}

func (e PackageResolvedExtractor) Extract(f lockfile.DepFile, _ lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var resolved packageResolvedFile

	if err := json.NewDecoder(f).Decode(&resolved); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	// Normalize pins from v1 or v2/v3 into a common representation.
	type normalizedPin struct {
		identity string
		repoURL  string
		version  string
		revision string
		kind     string // "remoteSourceControl", "localSourceControl", "registry", or "" for v1
	}

	var pins []normalizedPin

	switch resolved.Version {
	case 1:
		if resolved.Object == nil {
			return []lockfile.PackageDetails{}, nil
		}

		for _, pin := range resolved.Object.Pins {
			pins = append(pins, normalizedPin{
				repoURL:  pin.RepositoryURL,
				version:  pin.State.Version,
				revision: pin.State.Revision,
			})
		}
	case 2, 3:
		for _, pin := range resolved.Pins {
			pins = append(pins, normalizedPin{
				identity: pin.Identity,
				repoURL:  pin.Location,
				version:  pin.State.Version,
				revision: pin.State.Revision,
				kind:     pin.Kind,
			})
		}
	default:
		// Unknown version or empty JSON — return empty
		return []lockfile.PackageDetails{}, nil
	}

	packages := make([]lockfile.PackageDetails, 0, len(pins))

	for _, pin := range pins {
		// Skip localSourceControl pins (v2/v3)
		if pin.kind == "localSourceControl" {
			continue
		}

		// For v1, skip if the URL looks like a local path (no scheme or file:// scheme)
		if resolved.Version == 1 {
			if isLocalURL(pin.repoURL) {
				continue
			}
		}

		var name string
		if pin.kind == "registry" {
			// Registry pins have an identity (e.g. "scope.name") and an empty location.
			name = pin.identity
		} else {
			name = nameFromRepoURL(pin.repoURL)
		}

		if name == "" {
			continue
		}

		packages = append(packages, lockfile.PackageDetails{
			Name:           name,
			Version:        pin.version,
			Commit:         pin.revision,
			PackageManager: swiftPackageManager,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		})
	}

	return packages, nil
}

// nameFromRepoURL extracts a purl-compatible name from a repository URL.
// For "https://github.com/Alamofire/Alamofire.git" it returns "github.com/Alamofire/Alamofire".
// For scp-style SSH URLs like "git@github.com:org/repo.git" it returns "github.com/org/repo".
func nameFromRepoURL(repoURL string) string {
	// Handle scp-style SSH URLs (e.g. git@github.com:org/repo.git) which url.Parse
	// does not recognise as having a host.
	if m := scpStyleRegexp.FindStringSubmatch(repoURL); m != nil {
		host := m[1]
		path := strings.TrimSuffix(m[2], ".git")
		if path == "" {
			return ""
		}

		return host + "/" + path
	}

	parsed, err := url.Parse(repoURL)
	if err != nil || parsed.Host == "" {
		return ""
	}

	// Trim leading slash and trailing .git
	path := strings.TrimPrefix(parsed.Path, "/")
	path = strings.TrimSuffix(path, ".git")

	if path == "" {
		return ""
	}

	return parsed.Host + "/" + path
}

// isLocalURL returns true if the URL is a local file path (no scheme or file:// scheme).
func isLocalURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true // If we can't parse it, treat as local
	}

	return parsed.Scheme == "" || parsed.Scheme == "file"
}

var _ lockfile.Extractor = PackageResolvedExtractor{}

var swiftExtractor = PackageResolvedExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PackageSwiftMatcher{}}},
}

// ParsePackageResolved is a convenience function for testing.
func ParsePackageResolved(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, swiftExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.SwiftFilePath, swiftExtractor)
}
