package java

import (
	"bufio"
	"fmt"
	"io"
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

// GetArtifact extracts a ScannedArtifact from a Gradle lockfile by reading the
// project-level group assignment from the accompanying build.gradle or
// build.gradle.kts file. The artifact name is "group:projectDirName".
func (e GradleLockExtractor) GetArtifact(f extractor.DepFile, ctx extractor.ScanContext) (*models.ScannedArtifact, error) {
	if !ctx.ExtractMavenPomArtifactIds {
		return nil, nil
	}

	group, buildFilePath := extractGradleGroup(f)
	if group == "" {
		return nil, nil
	}

	projectName := filepath.Base(filepath.Dir(f.Path()))

	return &models.ScannedArtifact{
		ArtifactDetail: models.ArtifactDetail{
			Name:      group + ":" + projectName,
			Filename:  buildFilePath,
			Ecosystem: models.EcosystemMaven,
		},
	}, nil
}

// extractGradleGroup reads the project-level group assignment from a
// build.gradle or build.gradle.kts file adjacent to the lockfile.
// It matches only top-level "group = 'value'" or 'group = "value"' assignments,
// NOT dependency kwargs like "group: 'x'" or method calls like "group("x")".
func extractGradleGroup(f extractor.DepFile) (group string, buildFilePath string) {
	groupRegex := cachedregexp.MustCompile(`(?m)^[\t ]*group\s*=\s*['"]([^'"]+)['"]`)

	for _, name := range []string{buildGradleFilename, buildGradleKtsFilename} {
		candidate := filepath.Join(filepath.Dir(f.Path()), name)
		df, err := f.Open(candidate)
		if err != nil {
			continue
		}

		content, err := io.ReadAll(df)
		_ = df.Close()
		if err != nil {
			continue
		}

		matches := groupRegex.FindSubmatch(content)
		if matches != nil {
			return string(matches[1]), candidate
		}
	}

	return "", ""
}

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
