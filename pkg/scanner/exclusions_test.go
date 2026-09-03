package scanner

import (
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/golang"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	extractorpython "github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	extractorsystem "github.com/DataDog/datadog-sbom-generator/pkg/extractor/system"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestMatchCLIExclusion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		scanRoot        string
		path            string
		cliExcludePaths []string
		expectedMatched bool
		expectedPattern string
		expectError     bool
	}{
		{
			name:            "matches nested file pattern",
			scanRoot:        "project",
			path:            filepath.Join("project", "subdir", "file.txt"),
			cliExcludePaths: []string{filepath.Join("subdir", "*")},
			expectedMatched: true,
			expectedPattern: filepath.Join("subdir", "*"),
		},
		{
			name:            "matches test directory exclusion",
			scanRoot:        "project",
			path:            filepath.Join("project", "tests", "package-lock.json"),
			cliExcludePaths: []string{filepath.Join("tests", "*")},
			expectedMatched: true,
			expectedPattern: filepath.Join("tests", "*"),
		},
		{
			name:            "does not use prefix matching for plain paths",
			scanRoot:        "project",
			path:            filepath.Join("project", "tests", "unit", "package-lock.json"),
			cliExcludePaths: []string{"tests"},
			expectedMatched: false,
			expectedPattern: "",
		},
		{
			name:            "invalid pattern returns error",
			scanRoot:        "project",
			path:            filepath.Join("project", "file.txt"),
			cliExcludePaths: []string{"["},
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matched, pattern, err := matchCLIExclusion(tt.scanRoot, tt.path, tt.cliExcludePaths)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expectedMatched, matched)
			assert.Equal(t, tt.expectedPattern, pattern)
		})
	}
}

func TestMatchConfigExclusion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		repoRoot           string
		path               string
		configExcludePaths []string
		expectedMatched    bool
		expectedPattern    string
	}{
		{
			name:               "plain path matches descendant path by prefix",
			repoRoot:           "repo",
			path:               "repo/dist/file.txt",
			configExcludePaths: []string{"dist"},
			expectedMatched:    true,
			expectedPattern:    "dist",
		},
		{
			name:               "plain path does not match sibling prefix",
			repoRoot:           "repo",
			path:               "repo/distribution/file.txt",
			configExcludePaths: []string{"dist"},
			expectedMatched:    false,
			expectedPattern:    "",
		},
		{
			name:               "doublestar matches nested file",
			repoRoot:           "repo",
			path:               "repo/nested/deep/file.lock",
			configExcludePaths: []string{"**/*.lock"},
			expectedMatched:    true,
			expectedPattern:    "**/*.lock",
		},
		{
			name:               "empty repo root skips config matching",
			repoRoot:           "",
			path:               "repo/dist/file.txt",
			configExcludePaths: []string{"dist"},
			expectedMatched:    false,
			expectedPattern:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockReporter := reporter.NewMockReporter(ctrl)
			mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

			matched, pattern := matchConfigExclusion(tt.repoRoot, tt.path, tt.configExcludePaths, mockReporter)
			assert.Equal(t, tt.expectedMatched, matched)
			assert.Equal(t, tt.expectedPattern, pattern)
		})
	}
}

func TestEcosystemForExtractor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		extractor extractor.Extractor
		expected  models.Ecosystem
		expectOK  bool
	}{
		{
			name:      "npm lockfile extractor resolves to npm",
			extractor: javascript.NpmExtractor,
			expected:  models.EcosystemNPM,
			expectOK:  true,
		},
		{
			name:      "go lockfile extractor resolves to Go",
			extractor: golang.GoLockExtractor{},
			expected:  models.EcosystemGo,
			expectOK:  true,
		},
		{
			name:      "dpkg extractor resolves to Debian despite an Unknown package manager",
			extractor: extractorsystem.DpkgExtractor,
			expected:  models.EcosystemDebian,
			expectOK:  true,
		},
		{
			name:      "apk extractor resolves to Alpine despite an Unknown package manager",
			extractor: extractorsystem.ApkExtractor,
			expected:  models.EcosystemAlpine,
			expectOK:  true,
		},
		{
			name:      "pyproject.toml extractor resolves to PyPI despite an Unknown package manager",
			extractor: extractorpython.PyProjectExtractor,
			expected:  models.EcosystemPyPI,
			expectOK:  true,
		},
		{
			name:      "csv extractor ecosystem is not statically known",
			extractor: extractor.CSVExtractor{},
			expected:  "",
			expectOK:  false,
		},
		{
			name:      "osv scan results extractor ecosystem is not statically known",
			extractor: extractor.OSVScannerResultsExtractor{},
			expected:  "",
			expectOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			eco, ok := ecosystemForExtractor(tt.extractor)
			assert.Equal(t, tt.expectOK, ok)
			assert.Equal(t, tt.expected, eco)
		})
	}
}

func TestMatchEcosystemExclusion(t *testing.T) {
	t.Parallel()

	npmExtractor := javascript.NpmExtractor
	csvExtractor := extractor.CSVExtractor{}

	tests := []struct {
		name                    string
		extractor               extractor.Extractor
		configExcludeEcosystems []string
		expectedMatched         bool
		expectedEcosystem       models.Ecosystem
	}{
		{
			name:                    "no configured ecosystems never match",
			extractor:               npmExtractor,
			configExcludeEcosystems: nil,
			expectedMatched:         false,
		},
		{
			name:                    "matches configured ecosystem",
			extractor:               npmExtractor,
			configExcludeEcosystems: []string{"npm"},
			expectedMatched:         true,
			expectedEcosystem:       models.EcosystemNPM,
		},
		{
			name:                    "does not match unrelated ecosystem",
			extractor:               npmExtractor,
			configExcludeEcosystems: []string{"Go"},
			expectedMatched:         false,
		},
		{
			name:                    "extractor with unknown ecosystem never matches",
			extractor:               csvExtractor,
			configExcludeEcosystems: []string{"npm"},
			expectedMatched:         false,
		},
		{
			name:                    "case-mismatched ecosystem never matches",
			extractor:               npmExtractor,
			configExcludeEcosystems: []string{"NPM"},
			expectedMatched:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matched, eco := matchEcosystemExclusion(tt.extractor, tt.configExcludeEcosystems)
			assert.Equal(t, tt.expectedMatched, matched)
			assert.Equal(t, tt.expectedEcosystem, eco)
		})
	}
}

func TestMatchPackageExclusion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                  string
		pkg                   extractor.PackageDetails
		configExcludePackages []string
		expectedMatched       bool
	}{
		{
			name:                  "no configured packages never match",
			pkg:                   extractor.PackageDetails{Ecosystem: models.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
			configExcludePackages: nil,
			expectedMatched:       false,
		},
		{
			name:                  "matches configured ecosystem:name regardless of version",
			pkg:                   extractor.PackageDetails{Ecosystem: models.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
			configExcludePackages: []string{"npm:lodash"},
			expectedMatched:       true,
		},
		{
			name:                  "does not match unrelated package",
			pkg:                   extractor.PackageDetails{Ecosystem: models.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
			configExcludePackages: []string{"npm:express"},
			expectedMatched:       false,
		},
		{
			name:                  "does not match same name in a different ecosystem",
			pkg:                   extractor.PackageDetails{Ecosystem: models.EcosystemGo, Name: "lodash", Version: "1.0.0"},
			configExcludePackages: []string{"npm:lodash"},
			expectedMatched:       false,
		},
		{
			name:                  "case-mismatched ecosystem prefix never matches",
			pkg:                   extractor.PackageDetails{Ecosystem: models.EcosystemNPM, Name: "lodash", Version: "4.17.21"},
			configExcludePackages: []string{"NPM:lodash"},
			expectedMatched:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			matched := matchPackageExclusion(tt.pkg, tt.configExcludePackages)
			assert.Equal(t, tt.expectedMatched, matched)
		})
	}
}
