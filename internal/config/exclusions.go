package config

import (
	"errors"
	"os"

	ddhttp "github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// FetchExclusions returns ignore-path exclusions from local unified config and,
// when Datadog authentication is available, from the merged remote config.
func FetchExclusions(dir string, baseURL string, jwtToken string, exitOnFetchFailure bool, r reporter.Reporter) ([]string, string, error) {
	info, err := findRepositoryInfo(dir)
	if err != nil {
		// not a git repo or unresolvable worktree — no exclusions to apply
		return nil, "", nil //nolint:nilerr
	}

	localConfig := readLocalConfig(info.RootDir, r)

	hasDatadogAuth := ddhttp.HasDatadogAuth(jwtToken)
	if !hasDatadogAuth {
		if localConfig != nil {
			r.Infof("[config] No Datadog authentication available, using local configuration only\n")
		}

		return extractIgnorePaths(localConfig, r), info.RootDir, nil
	}

	if info.RemoteURL == "" {
		if localConfig != nil {
			r.Warnf("[config] Failed to resolve repository remote URL, continuing with local configuration\n")
			return extractIgnorePaths(localConfig, r), info.RootDir, nil
		}

		return nil, info.RootDir, nil
	}

	r.Infof("[config] Fetching merged configuration for %s\n", info.RemoteURL)
	mergedConfig, err := ddhttp.PostGetMergedConfig(info.RemoteURL, localConfig, baseURL, jwtToken)
	if err != nil {
		if exitOnFetchFailure {
			return nil, info.RootDir, models.ErrAPIFailed
		}

		if localConfig != nil {
			r.Warnf("[config] Failed to fetch merged configuration, continuing with local configuration: %v\n", err)
			return extractIgnorePaths(localConfig, r), info.RootDir, nil
		}

		r.Warnf("[config] Failed to fetch merged configuration, continuing without unified exclusions: %v\n", err)

		return nil, info.RootDir, nil
	}

	return extractIgnorePaths(&mergedConfig, r), info.RootDir, nil
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

func extractIgnorePaths(contents *string, r reporter.Reporter) []string {
	if contents == nil {
		return nil
	}

	cfg, err := parseUnifiedConfig(*contents)
	if err != nil {
		r.Warnf("[config] Failed to parse configuration: %v\n", err)
		return nil
	}

	return cfg.SCA.IgnorePaths
}
