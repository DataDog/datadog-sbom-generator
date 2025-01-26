package lockfile

import (
	"errors"
	"sort"
	"strings"

	"github.com/datadog/datadog-sbom-generator/pkg/models"
)

type DepGroup string

const (
	DepGroupUnknown                    DepGroup = "unknown"
	DepGroupDev                        DepGroup = "dev"
	DepGroupProd                       DepGroup = "prod"
	DepGroupOptional                   DepGroup = "optional"
	DepGroupRequires                   DepGroup = "requires"
	DepGroupBuildRequires              DepGroup = "build-requires"
	DepGroupPythonRequires             DepGroup = "python-requires"
	DepGroupDevelopmentOnly            DepGroup = "developmentOnly"
	DepGroupRuntimeClasspath           DepGroup = "runtimeClasspath"
	DepGroupCompileClasspath           DepGroup = "compileClasspath"
	DepGroupAnnotationProcessor        DepGroup = "annotationProcessor"
	DepGroupProductionRuntimeClasspath DepGroup = "productionRuntimeClasspath"
	DepGroupTest                       DepGroup = "test"
	DepGroupTestRuntimeClasspath       DepGroup = "testRuntimeClasspath"
)

var depGroupFromString = map[string]DepGroup{
	"dev":                        DepGroupDev,
	"prod":                       DepGroupProd,
	"optional":                   DepGroupOptional,
	"test":                       DepGroupTest,
	"requires":                   DepGroupRequires,
	"build-requires":             DepGroupBuildRequires,
	"python-requires":            DepGroupPythonRequires,
	"developmentOnly":            DepGroupDevelopmentOnly,
	"runtimeClasspath":           DepGroupRuntimeClasspath,
	"compileClasspath":           DepGroupCompileClasspath,
	"annotationProcessor":        DepGroupAnnotationProcessor,
	"productionRuntimeClasspath": DepGroupProductionRuntimeClasspath,
	"testRuntimeClasspath":       DepGroupTestRuntimeClasspath,
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

// Merge the dependency groups and make sure they are sorted
func MergeDepGroups(group1 []DepGroup, group2 []DepGroup) []DepGroup {
	allGroups := make(map[DepGroup]bool)
	for _, group := range group1 {
		allGroups[group] = true
	}
	for _, group := range group2 {
		allGroups[group] = true
	}

	keys := make([]DepGroup, 0, len(allGroups))

	// get all the keys from the map
	for k := range allGroups {
		keys = append(keys, k)
	}

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
