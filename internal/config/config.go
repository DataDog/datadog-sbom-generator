package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const ConfigFileBaseName = "code-security.datadog"

var configFileExtensions = []string{"yaml", "yml"}

// CodeSecurityConfig represents the structure of a code-security.datadog.yaml file.
type CodeSecurityConfig struct {
	SchemaVersion string    `yaml:"schema-version"`
	SCA           SCAConfig `yaml:"sca"`
}

// SCAConfig holds SCA-specific configuration.
type SCAConfig struct {
	IgnorePaths []string `yaml:"ignore-paths"`
}

// ReadConfigFile reads the code-security.datadog.yaml (or .yml) file from the given directory.
// Returns the raw file contents as a string.
// Returns an error wrapping os.ErrNotExist if no config file is found.
func ReadConfigFile(dir string) (string, error) {
	for _, ext := range configFileExtensions {
		configPath := filepath.Join(dir, fmt.Sprintf("%s.%s", ConfigFileBaseName, ext))
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

// ParseConfig parses the YAML contents of a code-security.datadog config file.
func ParseConfig(data string) (*CodeSecurityConfig, error) {
	var config CodeSecurityConfig
	if err := yaml.Unmarshal([]byte(data), &config); err != nil {
		return nil, fmt.Errorf("could not parse configuration file: %w", err)
	}
	return &config, nil
}
