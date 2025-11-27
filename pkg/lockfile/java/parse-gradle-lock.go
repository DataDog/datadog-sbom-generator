package java

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (lockfile.PackageDetails, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return lockfile.PackageDetails{}, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	var scopes []string
	group, artifact := parts[0], parts[1]
	version, scopesStr, found := strings.Cut(parts[2], "=")

	if found {
		scopes = strings.Split(scopesStr, ",")
	}

	return lockfile.PackageDetails{
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

func (e GradleLockExtractor) Extract(f lockfile.DepFile) ([]lockfile.PackageDetails, error) {
	pkgs := make([]lockfile.PackageDetails, 0)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		lockLine := strings.TrimSpace(scanner.Text())
		if !isGradleLockFileDepLine(lockLine) {
			continue
		}

		pkg, err := parseToGradlePackageDetail(lockLine)
		if err != nil {
			continue
		}

		pkgs = append(pkgs, pkg)
	}

	if err := scanner.Err(); err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("failed to read: %w", err)
	}

	return pkgs, nil
}

var GradleExtractor = GradleLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&BuildGradleMatcher{}}},
}

func ParseGradleLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, GradleExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.GradleFilePath, GradleExtractor)
}
