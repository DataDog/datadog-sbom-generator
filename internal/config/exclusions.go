package config

import (
	"errors"
	"os"

	ddhttp "github.com/DataDog/datadog-sbom-generator/internal/http"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
)

// FetchExclusions returns ignore-path exclusions from local unified config and,
// when Datadog authentication is available, from the merged remote config.
func FetchExclusions(dir string, baseURL string, jwtToken string, r reporter.Reporter) ([]string, error) {
	localConfig := readLocalConfig(dir, r)

	hasDatadogAuth := ddhttp.HasDatadogAuth(jwtToken)
	if !hasDatadogAuth && localConfig == nil {
		return nil, nil
	}

	if !hasDatadogAuth {
		r.Infof("[config] No Datadog authentication available, using local configuration only\n")
		return extractIgnorePaths(localConfig, r), nil
	}

	remoteURL, err := findRepositoryRemoteURL(dir)
	if err != nil {
		if localConfig != nil {
			return extractIgnorePaths(localConfig, r), nil
		}

		return nil, nil
	}

	r.Infof("[config] Fetching merged configuration for %s\n", remoteURL)
	mergedConfig, err := ddhttp.PostGetMergedConfig(remoteURL, localConfig, baseURL, jwtToken)
	if err != nil {
		if localConfig != nil {
			r.Warnf("[config] Failed to fetch merged configuration, continuing with local configuration: %v\n", err)
			return extractIgnorePaths(localConfig, r), nil
		}

		r.Warnf("[config] Failed to fetch merged configuration, continuing without unified exclusions: %v\n", err)

		return nil, nil
	}

	return extractIgnorePaths(&mergedConfig, r), nil
}

func readLocalConfig(dir string, r reporter.Reporter) *string {
	repo, err := findRepositoryRoot(dir)
	if err != nil {
		return nil
	}

	localConfigContents, err := readLocalConfigContents(repo.RootDir)
	if err == nil {
		return &localConfigContents
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
