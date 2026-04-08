package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const configFileBaseName = "code-security.datadog"

var configFileExtensions = []string{"yaml", "yml"}

// UnifiedConfig is the parsed contents of a code-security.datadog YAML file.
type UnifiedConfig struct {
	SchemaVersion string    `yaml:"schema-version"`
	SCA           SCAConfig `yaml:"sca"`
}

type SCAConfig struct {
	IgnorePaths []string `yaml:"ignore-paths"`
}

// ReadLocalConfigContents reads the contents of code-security.datadog.yaml or
// code-security.datadog.yml from dir and returns the file contents as a string.
// It returns an error wrapping os.ErrNotExist if neither file exists.
func ReadLocalConfigContents(dir string) (string, error) {
	for _, ext := range configFileExtensions {
		configPath := filepath.Join(dir, fmt.Sprintf("%s.%s", configFileBaseName, ext))
		data, err := os.ReadFile(configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}

			return "", fmt.Errorf("could not read configuration file %s: %w", configPath, err)
		}

		return string(data), nil
	}

	return "", fmt.Errorf("no configuration file found in %s: %w", dir, os.ErrNotExist)
}

// Parse unmarshals unified configuration YAML contents into a UnifiedConfig.
func Parse(contents string) (*UnifiedConfig, error) {
	var cfg UnifiedConfig
	if err := yaml.Unmarshal([]byte(contents), &cfg); err != nil {
		return nil, fmt.Errorf("could not parse configuration file: %w", err)
	}

	return &cfg, nil
}
