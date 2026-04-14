package python

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

	"github.com/BurntSushi/toml"
)

func (e UvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == models.UvFilePath.String()
}

func (e UvLockExtractor) IsOfficiallySupported() bool {
	return uvOfficiallySupported
}

func (e UvLockExtractor) PackageManager() models.PackageManager {
	return uvPackageManager
}

func extractNames(deps []uvDependency) map[string]struct{} {
	names := make(map[string]struct{}, len(deps))
	for _, dep := range deps {
		names[dep.Name] = struct{}{}
	}

	return names
}

// This link shows how roots are defined
// https://docs.astral.sh/uv/reference/settings/#build-backend_module-root
func isRoot(pkg *UvLockPackage) bool {
	return pkg.Source.Editable == "." || pkg.Source.Virtual == "."
}

func findRootPackage(allPackages []*UvLockPackage) (*UvLockPackage, error) {
	var rootPackage []*UvLockPackage
	for _, pkg := range allPackages {
		if isRoot(pkg) {
			rootPackage = append(rootPackage, pkg)
		}
	}

	// Lock file must have one root
	// https://github.com/astral-sh/uv/blob/f80ddf10b63c3e7b421ca4658e63f97db1e0378c/crates/uv/src/commands/project/lock.rs#L933-L936
	if len(rootPackage) == 0 {
		return nil, errors.New("no root package found in uv lockfile")
	}
	if len(rootPackage) > 1 {
		return nil, errors.New("uv lockfile cannot have more than one root")
	}

	return rootPackage[0], nil
}

func (e UvLockExtractor) Extract(f lockfile.DepFile, context lockfile.ScanContext) ([]lockfile.PackageDetails, error) {
	var parsedLockfile *UvLockFile

	content, err := io.ReadAll(f)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not read %s: %w", f.Path(), err)
	}

	_, err = toml.NewDecoder(bytes.NewReader(content)).Decode(&parsedLockfile)
	if err != nil {
		return []lockfile.PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	rootPackage, err := findRootPackage(parsedLockfile.Packages)
	if err != nil {
		return []lockfile.PackageDetails{}, errors.New("error getting root package")
	}

	// Compute BlockLocation for ALL toml packages (including root) using InTOML
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	allPositions := make([]models.FilePosition, len(parsedLockfile.Packages))
	positionPtrs := make([]*models.FilePosition, len(parsedLockfile.Packages))
	for i := range allPositions {
		positionPtrs[i] = &allPositions[i]
	}

	fileposition.InTOML("[[package]]", "", positionPtrs, lines)

	// This will hold packages we will return
	packages := make([]lockfile.PackageDetails, 0, len(parsedLockfile.Packages))
	if rootPackage != nil {
		directDependencies := extractNames(rootPackage.Dependencies)

		devDependencies := make(map[string]struct{})
		for _, deps := range rootPackage.DevDependencies {
			for _, dep := range deps {
				devDependencies[dep.Name] = struct{}{}
			}
		}

		for i, lockPackage := range parsedLockfile.Packages {
			// Skip root package because root files describe what it depends on, but isn't itself a dependency
			// https://docs.astral.sh/uv/concepts/projects/layout/
			if isRoot(lockPackage) {
				continue
			}

			_, commit, _ := strings.Cut(lockPackage.Source.Git, "#")
			_, isDirect := directDependencies[lockPackage.Name]
			_, isDevDependency := devDependencies[lockPackage.Name]

			depGroups := []string{}
			if isDevDependency {
				depGroups = append(depGroups, "dev")
			}

			blockLocation := allPositions[i]
			blockLocation.Filename = f.Path()

			pkgDetails := lockfile.PackageDetails{
				Name:           lockPackage.Name,
				Version:        lockPackage.Version,
				Commit:         commit,
				PackageManager: uvPackageManager,
				Ecosystem:      models.EcosystemPyPI,
				IsDirect:       isDirect || isDevDependency,
				BlockLocation:  blockLocation,
			LocationRole:   models.LocationRoleLockfile,
			}

			if len(depGroups) > 0 {
				pkgDetails.DepGroups = depGroups
			}

			packages = append(packages, pkgDetails)
		}
	}

	return packages, nil
}

var UvExtractor = UvLockExtractor{
	lockfile.WithMatcher{Matchers: []lockfile.Matcher{&PyprojectTOMLMatcher{}}},
}

func ParseUvLock(pathToLockfile string) ([]lockfile.PackageDetails, error) {
	return lockfile.ExtractFromFile(pathToLockfile, UvExtractor)
}

//nolint:gochecknoinits
func init() {
	lockfile.RegisterExtractor(models.UvFilePath, UvExtractor)
}
