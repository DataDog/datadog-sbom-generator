package lockfile

import (
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
	Version  int              `toml:"version"`
	Packages []*UvLockPackage `toml:"package"`

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

func buildDependencies(depList []uvDependency, allPkgs map[string]*UvLockPackage, directSet map[string]struct{}) []*PackageDetails {
	var deps []*PackageDetails
	for _, dep := range depList {
		if depPkg, ok := allPkgs[dep.Name]; ok {
			_, commit, _ := strings.Cut(depPkg.Source.Git, "#")
			_, isDirect := directSet[depPkg.Name]

			deps = append(deps, &PackageDetails{
				Name:           depPkg.Name,
				Version:        depPkg.Version,
				Commit:         commit,
				PackageManager: models.Uv,
				Ecosystem:      models.EcosystemPyPI,
				IsDirect:       isDirect,
			})
		}
	}
	return deps
}

func (e UvLockExtractor) Extract(f DepFile) ([]PackageDetails, error) {
	var parsedLockfile *UvLockFile

	_, err := toml.NewDecoder(f).Decode(&parsedLockfile)

	if err != nil {
		return []PackageDetails{}, fmt.Errorf("could not extract from %s: %w", f.Path(), err)
	}

	//Convert array of packages to a map to make lookup faster.
	parsedPackages := make(map[string]*UvLockPackage, len(parsedLockfile.Packages))
	var rootPackage *UvLockPackage
	for _, pkg := range parsedLockfile.Packages {
		parsedPackages[pkg.Name] = pkg
		if pkg.Source.Virtual == "." || pkg.Source.Editable == "." {
			rootPackage = pkg
		}
	}

	//This will hold packages we will return
	var packages []PackageDetails
	if rootPackage != nil {
		//Get the Direct Dependencies
		var directDependencies map[string]struct{}
		if len(parsedLockfile.Packages) > 0 {
			directDependencies = extractNames(rootPackage.Dependencies)
		}

		devDependencies := make(map[string]struct{})
		if len(parsedLockfile.Packages) > 0 {
			for _, deps := range rootPackage.DevDependencies {
				for _, dep := range deps {
					devDependencies[dep.Name] = struct{}{}
				}
			}
		}

		for _, lockPackage := range parsedLockfile.Packages {
			//Skip root package
			if lockPackage.Source.Virtual == "." || lockPackage.Source.Editable == "." {
				continue
			}

			_, commit, _ := strings.Cut(lockPackage.Source.Git, "#")

			_, isDirect := directDependencies[lockPackage.Name]

			_, isDevDependency := devDependencies[lockPackage.Name]
			depGroups := []string{}
			if isDevDependency {
				depGroups = append(depGroups, "dev")
			}

			if !isDirect && !isDevDependency {
				continue
			}
			pkgDetails := PackageDetails{
				Name:           lockPackage.Name,
				Version:        lockPackage.Version,
				Commit:         commit,
				PackageManager: models.Uv,
				Ecosystem:      models.EcosystemPyPI,
				IsDirect:       isDirect || isDevDependency,
				Dependencies:   buildDependencies(lockPackage.Dependencies, parsedPackages, directDependencies),
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
