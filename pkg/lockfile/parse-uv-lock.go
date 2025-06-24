package lockfile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

const (
	uvPackageManager      = models.Uv
	uvFilePath            = models.UvFilePath
	uvOfficiallySupported = true
)

type UvLockPackageSource struct {
	Registry string `toml:"registry,omitempty"`
	Git      string `toml:"git,omitempty"`
	Virtual  string `toml:"virtual,omitempty"`
	Editable string `toml:"editable,omitempty"`
}

type uvDependency struct {
	Name string `toml:"name"`
}

type uvPackageMetadata struct {
	RequiresDist []uvMetadata `toml:"requires-dist"`
}

type uvMetadata struct {
	Name      string `toml:"name"`
	Specifier string `toml:"specifier"`
}

type UvLockPackage struct {
	Name            string                    `toml:"name"`
	Version         string                    `toml:"version"`
	Source          UvLockPackageSource       `toml:"source"`
	Dependencies    []uvDependency            `toml:"dependencies"`
	DevDependencies map[string][]uvDependency `toml:"dev-dependencies"`
}

type UvLockFile struct {
	Version  int               `toml:"version"`
	Packages []*UvLockPackage  `toml:"package"`
	Metadata uvPackageMetadata `toml:"package.metadata"`
}

type UvLockExtractor struct {
	WithMatcher
}

func (e UvLockExtractor) ShouldExtract(path string) bool {
	return filepath.Base(path) == uvFilePath
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

func (e UvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *UvLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)
	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	rootPackage, err := findRootPackage(parsedLockfile.Packages)
	if err != nil {
		return []PackageDetails{}, errors.New("error getting root package")
	}

	// This will hold packages we will return
	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))
	if rootPackage != nil {
		directDependencies := extractNames(rootPackage.Dependencies)

		devDependencies := make(map[string]struct{})
		for _, deps := range rootPackage.DevDependencies {
			for _, dep := range deps {
				devDependencies[dep.Name] = struct{}{}
			}
		}

		for _, lockPackage := range parsedLockfile.Packages {
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

			pkgDetails := PackageDetails{
				Name:           lockPackage.Name,
				Version:        lockPackage.Version,
				Commit:         commit,
				PackageManager: uvPackageManager,
				Ecosystem:      models.EcosystemPyPI,
				IsDirect:       isDirect || isDevDependency,
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
	WithMatcher{Matchers: []Matcher{&PyprojectTOMLMatcher{}}},
}

//nolint:gochecknoinits
func init() {
	registerExtractor("uv.lock", UvExtractor)
}

func ParseUvLock(pathToLockfile string) ([]PackageDetails, error) {
	return ExtractFromFile(pathToLockfile, UvExtractor)
}
