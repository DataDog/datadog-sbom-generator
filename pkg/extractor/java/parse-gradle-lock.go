package java

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (extractor.PackageDetails, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return extractor.PackageDetails{}, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	var scopes []string
	group, artifact := parts[0], parts[1]
	version, scopesStr, found := strings.Cut(parts[2], "=")

	if found {
		scopes = strings.Split(scopesStr, ",")
	}

	return extractor.PackageDetails{
		Name:           fmt.Sprintf("%s:%s", group, artifact),
		Version:        version,
		PackageManager: gradlePackageManager,
		DepGroups:      scopes,
		Ecosystem:      models.EcosystemMaven,
	}, nil
}

func (e GradleLockExtractor) ShouldExtract(path string) bool {
	base := filepath.Base(path)

	for _, lockfile := range []string{models.GradleBuildScriptFilePath.String(), models.GradleFilePath.String()} {
		if lockfile == base {
			return true
		}
	}

	return false
}

func (e GradleLockExtractor) IsOfficiallySupported() bool {
	return gradleOfficiallySupported
}

func (e GradleLockExtractor) PackageManager() models.PackageManager {
	return gradlePackageManager
}

func (e GradleLockExtractor) Extract(f extractor.DepFile, context extractor.ScanContext) ([]extractor.PackageDetails, error) {
	pkgs := make([]extractor.PackageDetails, 0)
	scanner := bufio.NewScanner(f)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			continue
		}

		pkg.BlockLocation = models.FilePosition{
			Line:     models.Position{Start: lineNumber, End: lineNumber},
			Column:   models.Position{Start: 1, End: len(scanner.Text()) + 1},
			Filename: f.Path(),
		}
		pkg.LocationRole = models.LocationRoleLockfile

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return []extractor.PackageDetails{}, fmt.Errorf("failed to read: %w", err)
	}

	return pkgs, nil
}

// GetArtifact implements extractor.ArtifactExtractor.
// It looks for a build.gradle or build.gradle.kts file in the same directory
// as the lockfile, reads it to extract:
//   - the top-level group assignment (group:projectDir → artifact Name for findArtifact matching)
//   - project(':...') references → ProjectDeps for cross-subproject dependency edges
//
// If no build file is found, nil is returned.
func (e GradleLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
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

		// Set artifact.Name = "group:projectName" so findArtifact can match this
		// subproject when it appears as a dependency in another module's lockfile.
		// Group: prefer own build file; fall back to root build.gradle.
		// - Root project: inherits from allprojects { } only (subprojects { } does not apply).
		// - Subproject: inherits from allprojects { } or subprojects { }.
		// Name: prefer settings.gradle canonical name; fall back to directory basename.
		projectDir := filepath.Dir(f.Path())
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
				group = extractAllProjectsGroupFromRootBuildFile(ctx.RootDir)
			} else {
				// Subproject: allprojects { } and subprojects { } both apply.
				group = extractGroupFromRootBuildFile(ctx.RootDir)
			}
		}
		if group != "" {
			projectName := parseGradleSettingsProjectName(ctx.RootDir, projectDir)
			if projectName == "" {
				projectName = filepath.Base(projectDir)
			}
			artifact.Name = group + ":" + projectName
		}

		// Extract project(':submodule') references to build inter-module dep edges.
		if ctx.RootDir != "" {
			artifact.ProjectDeps = extractGradleProjectDeps(content, ctx.RootDir)
		}

		return artifact, nil
	}

	return nil, nil
}

// extractTopLevelGroup extracts the value of a top-level `group = "..."` or
// `group = '...'` assignment from Gradle build file content.
// It ignores dependency kwargs like `group: 'x'` or method calls like `group("x")`.
func extractTopLevelGroup(content []byte) string {
	groupRegex := cachedregexp.MustCompile(`(?m)^[\t ]*group\s*=\s*['"]([^'"]+)['"]`)
	if m := groupRegex.FindSubmatch(content); m != nil {
		return string(m[1])
	}

	return ""
}

// extractGradleProjectDeps parses project(':submodule') and project(':sub:module')
// references from Gradle build file content and returns ArtifactDetail entries
// whose Filename points to the corresponding build.gradle (or build.gradle.kts)
// under rootDir. Refs that cannot be resolved to an existing file are skipped.
func extractGradleProjectDeps(content []byte, rootDir string) []models.ArtifactDetail {
	projectRegex := cachedregexp.MustCompile(`project\(['"]([^'"]+)['"]\)`)
	matches := projectRegex.FindAllSubmatch(content, -1)

	var deps []models.ArtifactDetail
	seen := make(map[string]struct{})

	for _, m := range matches {
		ref := string(m[1]) // e.g. ":communication" or ":dd-java-agent:agent-tooling"
		// Convert Gradle project path to filesystem path: strip leading ':', replace ':' with '/'.
		subPath := strings.ReplaceAll(strings.TrimPrefix(ref, ":"), ":", string(filepath.Separator))

		for _, buildFileName := range []string{buildGradleFilename, buildGradleKtsFilename} {
			depPath := filepath.Join(rootDir, subPath, buildFileName)
			if _, err := os.Stat(depPath); err != nil {
				continue
			}
			if _, dup := seen[depPath]; dup {
				break
			}
			seen[depPath] = struct{}{}
			deps = append(deps, models.ArtifactDetail{Filename: depPath})

			break
		}
	}

	return deps
}

var _ extractor.ArtifactExtractor = GradleLockExtractor{}

var GradleExtractor = GradleLockExtractor{
	extractor.WithMatcher{Matchers: []extractor.Matcher{&BuildGradleMatcher{}}},
}

func ParseGradleLock(pathToLockfile string) ([]extractor.PackageDetails, error) {
	return extractor.ExtractFromFile(pathToLockfile, GradleExtractor)
}

//nolint:gochecknoinits
func init() {
	extractor.RegisterExtractor(models.GradleFilePath, GradleExtractor)
}
