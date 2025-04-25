package models

import "strings"

type Ecosystem string

const (
	EcosystemGo            Ecosystem = "Go"
	EcosystemNPM           Ecosystem = "npm"
	EcosystemOSSFuzz       Ecosystem = "OSS-Fuzz"
	EcosystemPyPI          Ecosystem = "PyPI"
	EcosystemRubyGems      Ecosystem = "RubyGems"
	EcosystemCratesIO      Ecosystem = "crates.io"
	EcosystemPackagist     Ecosystem = "Packagist"
	EcosystemMaven         Ecosystem = "Maven"
	EcosystemNuGet         Ecosystem = "NuGet"
	EcosystemLinux         Ecosystem = "Linux"
	EcosystemDebian        Ecosystem = "Debian"
	EcosystemAlpine        Ecosystem = "Alpine"
	EcosystemHex           Ecosystem = "Hex"
	EcosystemAndroid       Ecosystem = "Android"
	EcosystemGitHubActions Ecosystem = "GitHub Actions"
	EcosystemPub           Ecosystem = "Pub"
	EcosystemConanCenter   Ecosystem = "ConanCenter"
	EcosystemRockyLinux    Ecosystem = "Rocky Linux"
	EcosystemAlmaLinux     Ecosystem = "AlmaLinux"
	EcosystemBitnami       Ecosystem = "Bitnami"
	EcosystemPhotonOS      Ecosystem = "Photon OS"
	EcosystemCRAN          Ecosystem = "CRAN"
	EcosystemBioconductor  Ecosystem = "Bioconductor"
	EcosystemSwiftURL      Ecosystem = "SwiftURL"
)

// IsDevGroup returns if any string in groups indicates the development dependency group for the specified ecosystem.
func (sys Ecosystem) IsDevGroup(groups []string) bool {
	switch sys {
	case EcosystemNPM:
		return sys.isNpmDevGroup(groups)
	case EcosystemPackagist, EcosystemPyPI, EcosystemPub, EcosystemNuGet:
		return sys.isDevGroup(groups, string(DepGroupDev))
	case EcosystemConanCenter:
		return sys.isDevGroup(groups, "build-requires")
	case EcosystemMaven:
		return sys.isMavenDevGroup(groups)
	case EcosystemRubyGems:
		return isBundlerDevGroup(groups)
	case EcosystemGo, EcosystemOSSFuzz, EcosystemCratesIO, EcosystemLinux, EcosystemDebian, EcosystemAlpine, EcosystemHex, EcosystemAndroid, EcosystemGitHubActions, EcosystemRockyLinux, EcosystemAlmaLinux, EcosystemBitnami, EcosystemPhotonOS, EcosystemCRAN, EcosystemBioconductor, EcosystemSwiftURL:
		// Go does not have dev dependencies support
		// Other package managers are unsupported
		return false
	}

	return false
}

// isMavenDevGroup defines whether the dependency is only present in tests for the maven ecosystem or not (Maven and Gradle).
func (sys Ecosystem) isMavenDevGroup(groups []string) bool {
	if len(groups) == 0 {
		return false
	}

	for _, g := range groups {
		if !strings.HasPrefix(g, "test") {
			return false
		}
	}

	return true
}

func (sys Ecosystem) isNpmDevGroup(groups []string) bool {
	containsDev := false

	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if g != string(DepGroupDev) && g != string(DepGroupOptional) {
			return false
		} else if g == string(DepGroupDev) {
			containsDev = true
		}
	}

	return containsDev
}

func isBundlerDevGroup(groups []string) bool {
	if len(groups) == 0 {
		return false
	}

	for _, group := range groups {
		if _, isDevGroup := knownBundlerDevelopmentGroups[group]; !isDevGroup {
			return false
		}
	}

	return true
}

func (sys Ecosystem) isDevGroup(groups []string, devGroupName string) bool {
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
