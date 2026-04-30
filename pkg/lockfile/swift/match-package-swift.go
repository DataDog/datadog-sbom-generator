package swift

import (
	"bufio"
	"io"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

// PackageSwiftMatcher enriches packages extracted from Package.resolved with
// direct-dependency information from Package.swift.
type PackageSwiftMatcher struct{}

// urlRegexp matches the url: "..." argument in a .package(url: ...) declaration.
// TODO: Swift Package Registry dependencies use .package(id: "scope.name", from: "1.0.0")
// with no url: argument. These are never matched and will always be reported as IsDirect=false.
var urlRegexp = cachedregexp.MustCompile(`url:\s*"([^"]+)"`)

// packageEntry represents a .package(url: "...") declaration found in Package.swift.
type packageEntry struct {
	name    string // normalized name (same format as nameFromRepoURL)
	lineNum int    // 1-indexed line where .package( starts
	rawLine string // full source line where .package( appears (for column extraction)
}

// GetSourceFile opens Package.swift from the same directory as the lockfile.
//
// Note: Xcode can write the active lockfile at .swiftpm/configuration/Package.resolved,
// which is two levels below Package.swift. In that case this lookup will fail and no
// manifest enrichment will happen. Upward directory search is not implemented yet.
// GetSourceFile opens Package.swift from the same directory as the lockfile.
//
// Note: Xcode can write the active lockfile at .swiftpm/configuration/Package.resolved,
// which is two levels below Package.swift. In that case this lookup will fail and no
// manifest enrichment will happen. Upward directory search is not implemented yet.
func (m PackageSwiftMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	return f.Open("Package.swift")
}

func (m PackageSwiftMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, _ lockfile.ScanContext) error {
	entries, err := parsePackageSwift(sourceFile)
	if err != nil {
		return err
	}

	// Build a lookup map from normalized name to entry.
	// Keys are lowercased because GitHub URLs are case-insensitive: Package.swift and
	// Package.resolved may use different casings for the same repository URL.
	entryMap := make(map[string]packageEntry, len(entries))
	for _, entry := range entries {
		entryMap[strings.ToLower(entry.name)] = entry
	}

	// Enrich matching packages
	for i := range packages {
		entry, ok := entryMap[strings.ToLower(packages[i].Name)]
		if !ok {
			continue
		}

		packages[i].IsDirect = true
		packages[i].LocationRole = models.LocationRoleManifest
		packages[i].BlockLocation = models.FilePosition{
			Line:     models.Position{Start: entry.lineNum, End: entry.lineNum},
			Column:   models.Position{Start: fileposition.GetFirstNonEmptyCharacterIndexInLine(entry.rawLine), End: fileposition.GetLastNonEmptyCharacterIndexInLine(entry.rawLine)},
			Filename: sourceFile.Path(),
		}
	}

	return nil
}

// stripLineComment removes everything from the first // comment marker that is
// not part of a URL scheme (i.e. not preceded by :).
func stripLineComment(line string) string {
	for i := range len(line) - 1 {
		if line[i] == '/' && line[i+1] == '/' && (i == 0 || line[i-1] != ':') {
			return line[:i]
		}
	}

	return line
}

// scanParens counts parens in s starting at initialDepth and returns the final depth
// and the index just past the character that brought depth to zero (or -1 if depth
// never reached zero).
func scanParens(s string, initialDepth int) (depth int, closeIdx int) {
	for i, ch := range s {
		if ch == '(' {
			initialDepth++
		} else if ch == ')' {
			initialDepth--
			if initialDepth <= 0 {
				return initialDepth, i + 1
			}
		}
	}

	return initialDepth, -1
}

// parsePackageSwift reads a Package.swift file and extracts .package(url: "...") entries.
func parsePackageSwift(r io.Reader) ([]packageEntry, error) {
	scanner := bufio.NewScanner(r)
	var entries []packageEntry
	lineNum := 0

	var inBlock bool
	var blockStartLine int
	var blockStartRawLine string
	var blockLines strings.Builder
	var parenDepth int

	for scanner.Scan() {
		lineNum++
		rawLine := scanner.Text()
		line := stripLineComment(rawLine)

		if !inBlock {
			// A single line may contain multiple .package(...) calls; process all of them.
			rest := line
			for {
				idx := strings.Index(rest, ".package(")
				if idx < 0 {
					break
				}

				fragment := rest[idx:]
				depth, closeIdx := scanParens(fragment, 0)

				if closeIdx >= 0 {
					// Block is complete within this line segment.
					entry := extractEntryFromBlock(fragment[:closeIdx], lineNum, rawLine)
					if entry != nil {
						entries = append(entries, *entry)
					}
					rest = fragment[closeIdx:]
				} else {
					// Block spans multiple lines; hand off to the continuation path.
					inBlock = true
					blockStartLine = lineNum
					blockStartRawLine = rawLine
					blockLines.Reset()
					blockLines.WriteString(fragment)
					parenDepth = depth

					break
				}
			}
		} else {
			// Continue collecting a multi-line block.
			depth, closeIdx := scanParens(line, parenDepth)

			blockLines.WriteString("\n")
			if closeIdx >= 0 {
				blockLines.WriteString(line[:closeIdx])
				entry := extractEntryFromBlock(blockLines.String(), blockStartLine, blockStartRawLine)
				if entry != nil {
					entries = append(entries, *entry)
				}
				inBlock = false

				// Process the remainder of the line for more .package( calls.
				rest := line[closeIdx:]
				for {
					idx := strings.Index(rest, ".package(")
					if idx < 0 {
						break
					}

					fragment := rest[idx:]
					d, ci := scanParens(fragment, 0)

					if ci >= 0 {
						entry := extractEntryFromBlock(fragment[:ci], lineNum, rawLine)
						if entry != nil {
							entries = append(entries, *entry)
						}
						rest = fragment[ci:]
					} else {
						inBlock = true
						blockStartLine = lineNum
						blockStartRawLine = rawLine
						blockLines.Reset()
						blockLines.WriteString(fragment)
						parenDepth = d

						break
					}
				}
			} else {
				blockLines.WriteString(line)
				parenDepth = depth
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

// extractEntryFromBlock extracts the URL from a .package(...) block and derives the normalized name.
// rawLine is the original source line where .package( appears, used for column extraction.
func extractEntryFromBlock(block string, lineNum int, rawLine string) *packageEntry {
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
		rawLine: rawLine,
	}
}

var _ lockfile.Matcher = PackageSwiftMatcher{}
