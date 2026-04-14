package dart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"gopkg.in/yaml.v3"
)

const (
	pubsecPackageManager      = models.Pub
	pubsecFilePath            = models.PubFilePath
	pubsecOfficiallySupported = true
)

type PubspecLockDescription struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Path string `yaml:"path"`
	Ref  string `yaml:"resolved-ref"`
}

var _ yaml.Unmarshaler = &PubspecLockDescription{}

func (pld *PubspecLockDescription) UnmarshalYAML(value *yaml.Node) error {
	var m struct {
		Name string `yaml:"name"`
		URL  string `yaml:"url"`
		Path string `yaml:"path"`
		Ref  string `yaml:"resolved-ref"`
	}

	err := value.Decode(&m)

	if err == nil {
		pld.Name = m.Name
		pld.Path = m.Path
		pld.URL = m.URL
		pld.Ref = m.Ref

		return nil
	}

	var str *string

	err = value.Decode(&str)

	if err != nil {
		return err
	}

	pld.Path = *str

	return nil
}

type PubspecLockPackage struct {
	Source      string                 `yaml:"source"`
	Description PubspecLockDescription `yaml:"description"`
	Version     string                 `yaml:"version"`
	Dependency  string                 `yaml:"dependency"`
}

type PubspecLockfile struct {
	Packages map[string]PubspecLockPackage `yaml:"packages,omitempty"`
	Sdks     map[string]string             `yaml:"sdks"`
}

type PubspecLockExtractor struct{}

func (e PubspecLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.PubFilePath.String()
}

func (e PubspecLockExtractor) IsOfficiallySupported() bool {
	return pubsecOfficiallySupported
}

func (e PubspecLockExtractor) PackageManager() models.PackageManager {
	return pubsecPackageManager
}

// extractPubspecPackagePositions scans YAML lines for package entries under "packages:".
// Package names appear at 2-space indent (e.g. "  shelf:"), and their blocks extend
// until the next entry at the same or lesser indent level.
func extractPubspecPackagePositions(lines []string) map[string]models.FilePosition {
	positions := make(map[string]models.FilePosition)

	inPackages := false
	var currentName string
	var startLine int

	for i, line := range lines {
		lineNum := i + 1

		// Detect the "packages:" top-level key
		if strings.TrimSpace(line) == "packages:" {
			inPackages = true

			continue
		}

		if !inPackages {
			continue
		}

		// Check if we've left the packages section (non-indented, non-empty line)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// A line with no leading spaces means we've exited the packages block
		if len(line) > 0 && line[0] != ' ' {
			// Close current package if any
			if currentName != "" {
				pos := positions[currentName]
				pos.Line.End = i // previous line (1-indexed)
				pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[i-1])
				positions[currentName] = pos
				currentName = ""
			}

			inPackages = false

			continue
		}

		// 2-space indent: package name (e.g. "  shelf:")
		if len(line) >= 3 && line[0] == ' ' && line[1] == ' ' && line[2] != ' ' && strings.HasSuffix(trimmed, ":") {
			// Close previous package
			if currentName != "" {
				pos := positions[currentName]
				pos.Line.End = i // previous line (1-indexed)
				pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[i-1])
				positions[currentName] = pos
			}

			pkgName := strings.TrimSuffix(trimmed, ":")
			currentName = pkgName
			startLine = lineNum

			colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)

			positions[currentName] = models.FilePosition{
				Line:   models.Position{Start: startLine, End: 0}, // End will be set when block closes
				Column: models.Position{Start: colStart, End: 0},
			}

			continue
		}
	}

	// Close last package if file ended within packages section
	if currentName != "" {
		pos := positions[currentName]
		lastIdx := len(lines) - 1
		// Find last non-empty line
		for lastIdx >= 0 && strings.TrimSpace(lines[lastIdx]) == "" {
			lastIdx--
		}

		if lastIdx >= 0 {
			pos.Line.End = lastIdx + 1
			pos.Column.End = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[lastIdx])
		} else {
			pos.Line.End = pos.Line.Start
		}

		positions[currentName] = pos
	}

	return positions
}

func (e PubspecLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *PubspecLockfile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = yaml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)

	if err != nil && !errors.Is(err, io.EOF) {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}
	if parsedLockfile == nil {
		return []lockfile.PackageDetails{}, nil
	}

	lines := fileposition.BytesToLines(content)
	positions := extractPubspecPackagePositions(lines)

	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))

	for name, pkg := range parsedLockfile.Packages {
		pkgDetails := lockfile.PackageDetails{
			Name:           name,
			Version:        pkg.Version,
			Commit:         pkg.Description.Ref,
			PackageManager: pubsecPackageManager,
			Ecosystem:      models.EcosystemPub,
		}
		for _, str := range strings.Split(pkg.Dependency, " ") {
			if str == "dev" {
				pkgDetails.DepGroups = append(pkgDetails.DepGroups, "dev")
				break
			}
		}

		if pos, ok := positions[name]; ok {
			pos.Filename = f.Path()
			pkgDetails.BlockLocation = pos
		}

		packages = append(packages, pkgDetails)
	}

	return packages, nil
}

var _ lockfile.Extractor = PubspecLockExtractor{}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.PubFilePath, PubspecLockExtractor{})
}

func ParsePubspecLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, PubspecLockExtractor{})
}
