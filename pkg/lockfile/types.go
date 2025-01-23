package lockfile

import (
	"errors"
	"golang.org/x/exp/maps"
	"sort"
	"strings"

	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

type DepGroup string

const (
	DepGroupUnknown                     DepGroup = "unknown"
	DepGroupDev                         DepGroup = "dev"
	DepGroupProd                        DepGroup = "prod"
	DepGroupOptional                    DepGroup = "optional"
	DepGroupRequires                    DepGroup = "requires"
	DepGroupBuildRequires               DepGroup = "build-requires"
	DepGroupPythonRequires              DepGroup = "python-requires"
	DepGroupDevelopmentOnly             DepGroup = "developmentOnly"
	DepGroupRuntimeClasspath            DepGroup = "runtimeClasspath"
	DepGroupCompileClasspath            DepGroup = "compileClasspath"
	DepGroupAnnotationProcessor         DepGroup = "annotationProcessor"
	DepGroupProductionRuntimeClasspath  DepGroup = "productionRuntimeClasspath"
	DepGroupTest                        DepGroup = "test"
	DepGroupTestRuntimeClasspath        DepGroup = "testRuntimeClasspath"
	DepGroupMultiplePackagesConstrained DepGroup = "multiple-packages-constrained"
	DepGroupOnePackageConstrained       DepGroup = "one-package-constrained"
	DepGroupOnePackageUnconstrained     DepGroup = "one-package-unconstrained"
	DepGroupMultiplePackagesMixed       DepGroup = "multiple-packages-mixed"
	DepGroupFileFormatExample           DepGroup = "file-format-example"
	DepGroupNonNormalizedNames          DepGroup = "non-normalized-names"
	DepGroupCyclicRSelf                 DepGroup = "cyclic-r-self"
	DepGroupCyclicRComplex1             DepGroup = "cyclic-r-complex-1"
	DepGroupCyclicRComplex2             DepGroup = "cyclic-r-complex-1"
	DepGroupCyclicRComplex3             DepGroup = "cyclic-r-complex-1"
	DepGroupWithPerRequirementOptions   DepGroup = "with-per-requirement-options"
	DepGroupLineContinuation            DepGroup = "line-continuation"
	DepGroupEnvironmentMarkers          DepGroup = "environment-markers"
	DepGroupURLPackages                 DepGroup = "url-packages"
	DepGroupWhlUrlPackages              DepGroup = "whl-url-packages"
	DepGroupGeneratedSimple             DepGroup = "generated-simple"
	DepGroupGeneratedComplex            DepGroup = "generated-complex"
	DepGroupWithUrlROption              DepGroup = "with-url-r-option"
	DepGroupDuplicateRBase              DepGroup = "duplicate-r-base"
	DepGroupDuplicateRDev               DepGroup = "duplicate-r-dev"
	DepGroupDuplicateRTest              DepGroup = "duplicate-r-test"
	DepGroupWithAddedSupport            DepGroup = "with-added-support"
	DepGroupOtherFile                   DepGroup = "other-file"
	DepGroupWithMultipleOptions         DepGroup = "with-multiple-options"
	DepGroupWithMultipleROptions        DepGroup = "with-multiple-r-options"
)

var depGroupFromString = map[string]DepGroup{
	"dev":                           DepGroupDev,
	"prod":                          DepGroupProd,
	"optional":                      DepGroupOptional,
	"test":                          DepGroupTest,
	"requires":                      DepGroupRequires,
	"build-requires":                DepGroupBuildRequires,
	"python-requires":               DepGroupPythonRequires,
	"developmentOnly":               DepGroupDevelopmentOnly,
	"runtimeClasspath":              DepGroupRuntimeClasspath,
	"compileClasspath":              DepGroupCompileClasspath,
	"annotationProcessor":           DepGroupAnnotationProcessor,
	"productionRuntimeClasspath":    DepGroupProductionRuntimeClasspath,
	"testRuntimeClasspath":          DepGroupTestRuntimeClasspath,
	"multiplePackagesConstrained":   DepGroupMultiplePackagesConstrained,
	"onePackageConstrained":         DepGroupOnePackageConstrained,
	"onePackageUnconstrained":       DepGroupOnePackageUnconstrained,
	"multiplePackagesMixed":         DepGroupMultiplePackagesMixed,
	"non-normalized-names":          DepGroupNonNormalizedNames,
	"cyclic-r-self":                 DepGroupCyclicRSelf,
	"cyclic-r-complex-1":            DepGroupCyclicRComplex1,
	"cyclic-r-complex-2":            DepGroupCyclicRComplex2,
	"cyclic-r-complex-3":            DepGroupCyclicRComplex3,
	"with-per-requirement-options":  DepGroupWithPerRequirementOptions,
	"line-continuation":             DepGroupLineContinuation,
	"environment-markers":           DepGroupEnvironmentMarkers,
	"url-packages":                  DepGroupURLPackages,
	"whl-url-packages":              DepGroupWhlUrlPackages,
	"generated-simple":              DepGroupGeneratedSimple,
	"generated-complex":             DepGroupGeneratedComplex,
	"with-url-r-option":             DepGroupWithUrlROption,
	"duplicate-r-base":              DepGroupDuplicateRBase,
	"duplicate-r-dev":               DepGroupDuplicateRDev,
	"with-added-support":            DepGroupWithAddedSupport,
	"multiple-packages-mixed":       DepGroupMultiplePackagesMixed,
	"file-format-example":           DepGroupFileFormatExample,
	"duplicate-r-test":              DepGroupDuplicateRTest,
	"one-package-unconstrained":     DepGroupOnePackageUnconstrained,
	"one-package-constrained":       DepGroupOnePackageConstrained,
	"other-file":                    DepGroupOtherFile,
	"with-multiple-r-options":       DepGroupWithMultipleROptions,
	"with-multiple-options":         DepGroupWithMultipleOptions,
	"multiple-packages-constrained": DepGroupMultiplePackagesConstrained,
}

func GetDepGroupFromString(str string) (DepGroup, error) {
	if len(str) == 0 {
		return DepGroupUnknown, errors.New("dep group is empty")
	}

	depGroup, ok := depGroupFromString[str]
	if !ok {
		return DepGroupUnknown, errors.New("unknown dependency group: " + str)
	}

	return depGroup, nil
}

func (c DepGroup) String() string {
	return string(c)
}

func MergeDepGroups(group1 []DepGroup, group2 []DepGroup) []DepGroup {
	allGroups := make(map[DepGroup]bool)
	for _, group := range group1 {
		allGroups[group] = true
	}
	for _, group := range group2 {
		allGroups[group] = true
	}
	keys := maps.Keys(allGroups)
	sort.SliceStable(keys, func(i, j int) bool {
		return len(keys[i].String()) < len(keys[j].String())
	})

	return keys
}

type PackageDetails struct {
	Name            string                `json:"name"`
	Version         string                `json:"version"`
	TargetVersions  []string              `json:"targetVersions,omitempty"`
	Commit          string                `json:"commit,omitempty"`
	Ecosystem       Ecosystem             `json:"ecosystem,omitempty"`
	CompareAs       Ecosystem             `json:"compareAs,omitempty"`
	DepGroups       []DepGroup            `json:"-"`
	BlockLocation   models.FilePosition   `json:"blockLocation,omitempty"`
	VersionLocation *models.FilePosition  `json:"versionLocation,omitempty"`
	NameLocation    *models.FilePosition  `json:"nameLocation,omitempty"`
	PackageManager  models.PackageManager `json:"packageManager,omitempty"`
	IsDirect        bool                  `json:"isDirect,omitempty"`
	Dependencies    []*PackageDetails     `json:"dependencies,omitempty"`
}

type Ecosystem string

type PackageDetailsParser = func(pathToLockfile string) ([]PackageDetails, error)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func (sys Ecosystem) IsDevGroup(groups []DepGroup) bool {
	switch sys {
	case NpmEcosystem:
		// Also PnpmEcosystem(=NpmEcosystem) and YarnEcosystem(=NpmEcosystem)
		return sys.isNpmDevGroup(groups)
	case ComposerEcosystem, PipEcosystem, PubEcosystem, NuGetEcosystem:
		// Also PipenvEcosystem(=PipEcosystem,=PoetryEcosystem).
		return sys.isDevGroup(groups, DepGroupDev)
	case ConanEcosystem:
		return sys.isDevGroup(groups, "build-requires")
	case MavenEcosystem:
		return sys.isMavenDevGroup(groups)
	case AlpineEcosystem, DebianEcosystem, CargoEcosystem, BundlerEcosystem, GoEcosystem, MixEcosystem, CRANEcosystem:
		return false
	}

	return false
}

var mavenDepGroupForDev []DepGroup = []DepGroup{DepGroupTestRuntimeClasspath}

// isMavenDevGroup defines whether the dependency is only present in tests for the maven ecosystem or not (Maven and Gradle).
func (sys Ecosystem) isMavenDevGroup(groups []DepGroup) bool {
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if !strings.HasPrefix(strings.ToLower(g.String()), "test") {
			return false
		}
	}

	return true
}

func (sys Ecosystem) isNpmDevGroup(groups []DepGroup) bool {
	containsDev := false

	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if g != DepGroupDev && g != DepGroupOptional {
			return false
		} else if g == DepGroupDev {
			containsDev = true
		}
	}

	return containsDev
}

func (sys Ecosystem) isDevGroup(groups []DepGroup, devGroupName DepGroup) bool {
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if g != devGroupName {
			return false
		}
	}

	return true
}

func (pkg PackageDetails) IsVersionEmpty() bool {
	return pkg.Version == ""
}
