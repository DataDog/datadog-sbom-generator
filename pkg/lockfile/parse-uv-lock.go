package lockfile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/BurntSushi/toml"
)

type UvLockPackageSource struct {
	Registry string `toml:"registry,omitempty"`
	Git      string `toml:"git,omitempty"`
	Virtual  string `toml:"virtual,omitempty"`
	Editable string `toml:"editable,omitempty"`
}

type UvLockPackageSdist struct {
	URL        string `toml:"url"`
	Hash       string `toml:"hash"`
	Size       int    `toml:"size"`
	UploadTime string `toml:"upload-time"`
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
	Name                 string                    `toml:"name"`
	Version              string                    `toml:"version"`
	Source               UvLockPackageSource       `toml:"source"`
	Dependencies         []uvDependency            `toml:"dependencies"`
	OptionalDependencies map[string][]uvDependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvDependency `toml:"dev-dependencies"`
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
	return filepath.Base(path) == "uv.lock"
}

func extractNames(deps []uvDependency) map[string]struct{} {
	names := make(map[string]struct{}, len(deps))
	for _, dep := range deps {
		names[dep.Name] = struct{}{}
	}

	return names
}

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
		return []PackageDetails{}, fmt.Errorf("could not find root package: %w", err)
	}

	// This will hold packages we will return
	packages := make([]PackageDetails, 0, len(parsedLockfile.Packages))
	if rootPackage != nil {
		// Get the Direct Dependencies
		directDependencies := extractNames(rootPackage.Dependencies)

		devDependencies := make(map[string]struct{})
		for _, deps := range rootPackage.DevDependencies {
			for _, dep := range deps {
				devDependencies[dep.Name] = struct{}{}
			}
		}

		for _, lockPackage := range parsedLockfile.Packages {
			// Skip root package
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
				PackageManager: models.Uv,
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
