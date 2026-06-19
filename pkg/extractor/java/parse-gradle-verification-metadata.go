package java

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/internal/utility/fileposition"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func (e GradleVerificationMetadataExtractor) ShouldExtract(path string) bool {
	return filepath.Base(filepath.Dir(path)) == "gradle" && filepath.Base(path) == "verification-metadata.xml"
}

func (e GradleVerificationMetadataExtractor) IsOfficiallySupported() bool {
	return gradleVerificationOfficiallySupported
}

func (e GradleVerificationMetadataExtractor) PackageManager() models.PackageManager {
	return gradleVerificationPackageManager
}

// componentKey builds a unique key from a component's attributes for position lookup.
func componentKey(group, name, version string) string {
	return group + ":" + name + ":" + version
}

var componentStartRe = cachedregexp.MustCompile(`<component\s+group="([^"]+)"\s+name="([^"]+)"\s+version="([^"]+)"`)

// extractComponentPositions scans lines for <component> blocks and returns positions keyed by group:name:version.
// When the same group:name:version appears multiple times (multiple versions scenario),
// we store positions in order and consume them sequentially.
func extractComponentPositions(lines []string) map[string][]models.FilePosition {
	positions := make(map[string][]models.FilePosition)

	for i, line := range lines {
		matches := componentStartRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		group, name, version := matches[1], matches[2], matches[3]
		key := componentKey(group, name, version)
		lineNum := i + 1 // 1-indexed

		colStart := fileposition.GetFirstNonEmptyCharacterIndexInLine(line)
		colEnd := fileposition.GetLastNonEmptyCharacterIndexInLine(line)

		// Find the end of this component block (</component> or self-closing />)
		endLine := lineNum
		if !strings.Contains(line, "/>") {
			for j := i + 1; j < len(lines); j++ {
				if strings.Contains(lines[j], "</component>") {
					endLine = j + 1
					colEnd = fileposition.GetLastNonEmptyCharacterIndexInLine(lines[j])

					break
				}
			}
		}

		positions[key] = append(positions[key], models.FilePosition{
			Line:   models.Position{Start: lineNum, End: endLine},
			Column: models.Position{Start: colStart, End: colEnd},
		})
	}

	return positions
}

func (e GradleVerificationMetadataExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	var parsedLockfile *GradleVerificationMetadataFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	err = xml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	lines := fileposition.BytesToLines(content)
	positions := extractComponentPositions(lines)

	// Track consumption index per key for duplicate group:name:version entries
	consumed := make(map[string]int)

	pkgs := make([]extractor.PackageDetails, 0, len(parsedLockfile.Components))

	for _, component := range parsedLockfile.Components {
		key := componentKey(component.Group, component.Name, component.Version)

		pkg := extractor.PackageDetails{
			Name:           component.Group + ":" + component.Name,
			Version:        component.Version,
			PackageManager: gradleVerificationPackageManager,
			Ecosystem:      models.EcosystemMaven,
		}

		if posList, ok := positions[key]; ok {
			idx := consumed[key]
			if idx < len(posList) {
				pos := posList[idx]
				pos.Filename = f.Path()
				pkg.BlockLocation = pos
				pkg.LocationRole = models.LocationRoleLockfile
				consumed[key] = idx + 1
			}
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil
}

// GetArtifact implements extractor.ArtifactExtractor.
// verification-metadata.xml lives at <root>/gradle/verification-metadata.xml,
// so the build file is one level up (../build.gradle or ../build.gradle.kts).
// The build file is read to extract group and project deps, mirroring
// GradleLockExtractor.GetArtifact. If no build file is found, nil is returned.
func (e GradleVerificationMetadataExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	for _, name := range []string{"../" + buildGradleFilename, "../" + buildGradleKtsFilename} {
		buildFile, err := f.Open(name)
		if err != nil {
			continue
		}

		content, err := io.ReadAll(buildFile)
		buildFilePath := buildFile.Path()
		_ = buildFile.Close()
		if err != nil {
			return &models.ScannedArtifact{ArtifactDetail: models.ArtifactDetail{Filename: buildFilePath}}, err
		}

		artifact := &models.ScannedArtifact{
			ArtifactDetail: models.ArtifactDetail{
				Filename:  buildFilePath,
				Ecosystem: models.EcosystemMaven,
			},
		}

		// verification-metadata.xml is at <root>/gradle/; project dir is two levels up.
		// Group: prefer own build file; fall back to root build.gradle.
		// - Root project: inherits from allprojects { } only (subprojects { } does not apply).
		// - Subproject: inherits from allprojects { } or subprojects { }.
		// Name: prefer settings.gradle canonical name; fall back to directory basename.
		projectDir := filepath.Dir(filepath.Dir(f.Path()))
		group := extractTopLevelGroup(content)
		if group == "" && ctx.RootDir != "" {
			// Normalize to absolute so the root-vs-subproject check is reliable even
			// when the scanner is invoked with a relative path (e.g. "scan .").
			absRootDir := ctx.RootDir
			if abs, err := filepath.Abs(ctx.RootDir); err == nil {
				absRootDir = abs
			}
			if projectDir == absRootDir {
				// Root project: only allprojects { } applies.
				group = extractAllProjectsGroupFromRootBuildFile(absRootDir)
			} else {
				// Subproject: allprojects { } and subprojects { } both apply.
				group = extractGroupFromRootBuildFile(absRootDir)
			}
		}
		if group != "" {
			projectName := parseGradleSettingsProjectName(ctx.RootDir, projectDir)
			if projectName == "" {
				projectName = filepath.Base(projectDir)
			}
			artifact.Name = group + ":" + projectName
		}

		if ctx.RootDir != "" {
			artifact.ProjectDeps = extractGradleProjectDeps(content, ctx.RootDir)
		}

		return artifact, nil
	}

	return nil, nil
}

var _ extractor.ArtifactExtractor = GradleVerificationMetadataExtractor{}

var GradleVerificationExtractor = GradleVerificationMetadataExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&BuildGradleMatcher{}}},
}

func ParseGradleVerificationMetadata(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, GradleVerificationExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.GradleVerificationFilePath, GradleVerificationExtractor)
}
