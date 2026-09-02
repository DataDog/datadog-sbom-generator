package config

import (
	"errors"
	"os"

	ddhttp "github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// Exclusions holds the SCA scanning exclusions extracted from a unified config file.
type Exclusions struct {
	Paths      []string
	Ecosystems []string
}

// FetchExclusions returns ignore-path and ignore-ecosystem exclusions from local unified
// config and, when Datadog authentication is available, from the merged remote config.
func FetchExclusions(dir string, baseURL string, jwtToken string, exitOnFetchFailure bool, r reporter.Reporter) (Exclusions, string, error) {
	info, err := findRepositoryInfo(dir)
	if err != nil {
		// not a git repo or unresolvable worktree — no exclusions to apply
		return Exclusions{}, "", nil //nolint:nilerr
	}

	localConfig := readLocalConfig(info.RootDir, r)

	hasDatadogAuth := ddhttp.HasDatadogAuth(jwtToken)
	if !hasDatadogAuth {
		if localConfig != nil {
			r.Infof("[config] No Datadog authentication available, using local configuration only\n")
		}

		return extractExclusions(localConfig, r), info.RootDir, nil
	}

	if info.RemoteURL == "" {
		if localConfig != nil {
			r.Warnf("[config] Failed to resolve repository remote URL, continuing with local configuration\n")
			return extractExclusions(localConfig, r), info.RootDir, nil
		}

		return Exclusions{}, info.RootDir, nil
	}

	r.Infof("[config] Fetching merged configuration for %s\n", info.RemoteURL)
	mergedConfig, err := ddhttp.PostGetMergedConfig(info.RemoteURL, localConfig, baseURL, jwtToken)
	if err != nil {
		if exitOnFetchFailure {
			return Exclusions{}, info.RootDir, models.ErrAPIFailed
		}

		if localConfig != nil {
			r.Warnf("[config] Failed to fetch merged configuration, continuing with local configuration: %v\n", err)
			return extractExclusions(localConfig, r), info.RootDir, nil
		}

		r.Warnf("[config] Failed to fetch merged configuration, continuing without unified exclusions: %v\n", err)

		return Exclusions{}, info.RootDir, nil
	}

	return extractExclusions(&mergedConfig, r), info.RootDir, nil
}

func readLocalConfig(rootDir string, r reporter.Reporter) *string {
	contents, err := readLocalConfigContents(rootDir)
	if err == nil {
		return &contents
	}

	if !errors.Is(err, os.ErrNotExist) {
		r.Warnf("[config] Failed to read configuration file: %v\n", err)
	}

	return nil
}

func extractExclusions(contents *string, r reporter.Reporter) Exclusions {
	if contents == nil {
		return Exclusions{}
	}

	cfg, err := parseUnifiedConfig(*contents)
	if err != nil {
		r.Warnf("[config] Failed to parse configuration: %v\n", err)
		return Exclusions{}
	}

	for _, eco := range cfg.SCA.IgnoreEcosystems {
		if !models.IsKnownEcosystem(eco) {
			r.Warnf("[config] sca.ignore-ecosystems entry %q does not match any known ecosystem (check spelling and case) and will never match\n", eco)
		}
	}

	return Exclusions{Paths: cfg.SCA.IgnorePaths, Ecosystems: cfg.SCA.IgnoreEcosystems}
}
