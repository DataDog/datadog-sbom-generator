package swift

import (
	"bufio"
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// PackageSwiftMatcher enriches packages extracted from Package.resolved with
// direct-dependency information from Package.swift.
type PackageSwiftMatcher struct{}

var urlRegexp = cachedregexp.MustCompile(`url:\s*"([^"]+)"`)

// packageEntry represents a .package(url: "...") declaration found in Package.swift.
type packageEntry struct {
	name    string // normalized name (same format as nameFromRepoURL)
	lineNum int    // 1-indexed line where .package( starts
}

func (m PackageSwiftMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	return f.Open("Package.swift")
}

func (m PackageSwiftMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, _ lockfile.ScanContext) error {
	entries, err := parsePackageSwift(sourceFile)
	if err != nil {
		return err
	}

	// Build a lookup map from normalized name to entry
	entryMap := make(map[string]packageEntry, len(entries))
	for _, entry := range entries {
		entryMap[entry.name] = entry
	}

	// Enrich matching packages
	for i := range packages {
		entry, ok := entryMap[packages[i].Name]
		if !ok {
			continue
		}

		packages[i].IsDirect = true
		packages[i].LocationRole = models.LocationRoleManifest
		packages[i].BlockLocation = models.FilePosition{
			Line:     models.Position{Start: entry.lineNum, End: entry.lineNum},
			Column:   models.Position{Start: 0, End: 0},
			Filename: sourceFile.Path(),
		}
	}

	return nil
}

// parsePackageSwift reads a Package.swift file and extracts .package(url: "...") entries.
func parsePackageSwift(r io.Reader) ([]packageEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []packageEntry
	lineNum := 0

	var inBlock bool
	var blockStartLine int
	var blockLines strings.Builder
	var parenDepth int

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if !inBlock {
			// Look for .package( to start a dependency block
			idx := strings.Index(line, ".package(")
			if idx < 0 {
				continue
			}

			inBlock = true
			blockStartLine = lineNum
			blockLines.Reset()
			// Count parens from the .package( position onward
			parenDepth = 0
			for _, ch := range line[idx:] {
				if ch == '(' {
					parenDepth++
				} else if ch == ')' {
					parenDepth--
				}
			}
			blockLines.WriteString(line[idx:])

			if parenDepth <= 0 {
				// Block is complete on a single line
				entry := extractEntryFromBlock(blockLines.String(), blockStartLine)
				if entry != nil {
					entries = append(entries, *entry)
				}
				inBlock = false
			}
		} else {
			// Continue collecting the multi-line block
			for _, ch := range line {
				if ch == '(' {
					parenDepth++
				} else if ch == ')' {
					parenDepth--
				}
			}
			blockLines.WriteString("\n")
			blockLines.WriteString(line)

			if parenDepth <= 0 {
				entry := extractEntryFromBlock(blockLines.String(), blockStartLine)
				if entry != nil {
					entries = append(entries, *entry)
				}
				inBlock = false
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// extractEntryFromBlock extracts the URL from a .package(...) block and derives the normalized name.
func extractEntryFromBlock(block string, lineNum int) *packageEntry {
	matches := urlRegexp.FindStringSubmatch(block)
	if len(matches) < 2 {
		return nil
	}

	repoURL := matches[1]
	name := nameFromRepoURL(repoURL)
	if name == "" {
		return nil
	}

	return &packageEntry{
		name:    name,
		lineNum: lineNum,
	}
}

var _ lockfile.Matcher = PackageSwiftMatcher{}
