package lockfile

import (
	"bufio"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

const (
	gradleLockFileCommentPrefix = "#"
	gradleLockFileEmptyPrefix   = "empty="
)

func isGradleLockFileDepLine(line string) bool {
	ret := strings.HasPrefix(line, gradleLockFileCommentPrefix) ||
		strings.HasPrefix(line, gradleLockFileEmptyPrefix)

	return !ret
}

func parseToGradlePackageDetail(line string) (PackageDetails, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) < 3 {
		return PackageDetails{}, fmt.Errorf("invalid line in gradle lockfile: %s", line)
	}

	var scopes []DepGroup
	group, artifact := parts[0], parts[1]
	version, scopesStr, found := strings.Cut(parts[2], "=")

	if found {
		scopesString := strings.Split(scopesStr, ",")
		for _, scopeStr := range scopesString {
			depGroup, err := GetDepGroupFromString(scopeStr)

			if err == nil {
				scopes = append(scopes, depGroup)
			}
		}
	}

	return PackageDetails{
		Name:           fmt.Sprintf("%s:%s", group, artifact),
		Version:        version,
		PackageManager: models.Gradle,
		DepGroups:      scopes,
		Ecosystem:      MavenEcosystem,
		CompareAs:      MavenEcosystem,
	}, nil
}

type GradleLockExtractor struct {
	WithMatcher
}

func (e GradleLockExtractor) ShouldExtract(path string) bool {
	base := filepath.Base(path)

	for _, lockfile := range []string{"buildscript-gradle.lockfile", "gradle.lockfile"} {
		if lockfile == base {
			return true
		}
	}

	return false
}

func (e GradleLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	pkgs := make([]PackageDetails, 0)
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
		return []PackageDetails{}, fmt.Errorf("failed to read: %w", err)
	}

	return pkgs, nil
}

var GradleExtractor = GradleLockExtractor{
	WithMatcher{Matcher: BuildGradleMatcher{}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("gradle.lockfile", GradleExtractor)
}

func ParseGradleLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, GradleExtractor)
}
