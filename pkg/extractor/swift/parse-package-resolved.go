package swift

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// scpStyleRegexp matches scp-style SSH URLs like git@github.com:org/repo.git
var scpStyleRegexp = cachedregexp.MustCompile(`^[^@]+@([^:]+):(.+)$`)

// PackageResolvedExtractor extracts dependencies from Swift Package.resolved files (v1, v2, v3).
type PackageResolvedExtractor struct {
	extractor.WithMatcher
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

func (e PackageResolvedExtractor) Extract(f extractor.DepFile, _ extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var resolved packageResolvedFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	if err := json.NewDecoder(bytes.NewReader(content)).Decode(&resolved); err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	positions := pinPositionsByIdentity(lines)

	// Normalize pins from v1 or v2/v3 into a common representation.
	type normalizedPin struct {
		identity string
		repoURL  string
		version  string
		branch   string
		revision string
		kind     string // "remoteSourceControl", "localSourceControl", "registry", or "" for v1
	}

	var pins []normalizedPin

	switch resolved.Version {
	case 1:
		if resolved.Object == nil {
			return []extractor.PackageDetails{}, nil
		}

		for _, pin := range resolved.Object.Pins {
			pins = append(pins, normalizedPin{
				repoURL:  pin.RepositoryURL,
				version:  pin.State.Version,
				branch:   pin.State.Branch,
				revision: pin.State.Revision,
			})
		}
	case 2, 3:
		for _, pin := range resolved.Pins {
			pins = append(pins, normalizedPin{
				identity: pin.Identity,
				repoURL:  pin.Location,
				version:  pin.State.Version,
				branch:   pin.State.Branch,
				revision: pin.State.Revision,
				kind:     pin.Kind,
			})
		}
	default:
		// Unknown version or empty JSON — return empty
		return []extractor.PackageDetails{}, nil
	}

	packages := make([]extractor.PackageDetails, 0, len(pins))

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

		// Use branch as version when there is no version tag (branch-pinned dependency).
		version := pin.version
		if version == "" {
			version = pin.branch
		}

		pkgDetails := extractor.PackageDetails{
			Name:           name,
			Version:        version,
			Commit:         pin.revision,
			PackageManager: swiftPackageManager,
			Ecosystem:      models.EcosystemSwiftURL,
			IsDirect:       false,
			LocationRole:   models.LocationRoleLockfile,
		}

		if pos, ok := positions[pin.identity]; ok {
			blockLocation := *pos
			blockLocation.Filename = f.Path()
			pkgDetails.BlockLocation = blockLocation
		}

		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

// identityRegexp matches the "identity" key inside a pin object.
var identityRegexp = cachedregexp.MustCompile(`"identity"\s*:\s*"([^"]+)"`)

// pinPositionsByIdentity scans the raw JSON lines and returns a FilePosition for each
// pin block, keyed by the pin's identity value.  Each block starts at the "{" line
// that precedes the "identity" field and ends at the matching "}".
func pinPositionsByIdentity(lines []string) map[string]*models.FilePosition {
	positions := make(map[string]*models.FilePosition)

	for i, line := range lines {
		m := identityRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		identity := m[1]

		// Walk backwards to find the opening "{" of this pin block.
		blockStart := i
		for blockStart > 0 && !strings.Contains(lines[blockStart], "{") {
			blockStart--
		}

		// Walk forward to find the matching closing "}".
		depth := 0
		blockEnd := blockStart

		for blockEnd < len(lines) {
			for _, ch := range lines[blockEnd] {
				if ch == '{' {
					depth++
				} else if ch == '}' {
					depth--
				}
			}

			if depth <= 0 {
				break
			}

			blockEnd++
		}

		colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(lines[blockStart])
		colEnd := fileposition.GetLastNonEmptyCharacterIndexInLine(lines[blockEnd])

		if colStart < 1 {
			colStart = 1
		}

		if colEnd < 1 {
			colEnd = 1
		}

		positions[identity] = &models.FilePosition{
			Line:   models.Position{Start: blockStart + 1, End: blockEnd + 1},
			Column: models.Position{Start: colStart, End: colEnd},
		}
	}

	return positions
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

var _ extractor.Extractor = PackageResolvedExtractor{}

var swiftExtractor = PackageResolvedExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&PackageSwiftMatcher{}}},
}

// ParsePackageResolved is a convenience function for testing.
func ParsePackageResolved(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, swiftExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.SwiftFilePath, swiftExtractor)
}
