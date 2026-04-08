package scanner

import (
	"testing"

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
			path:            "project/subdir/file.txt",
			cliExcludePaths: []string{"subdir/*"},
			expectedMatched: true,
			expectedPattern: "subdir/*",
		},
		{
			name:            "matches test directory exclusion",
			scanRoot:        "project",
			path:            "project/tests/package-lock.json",
			cliExcludePaths: []string{"tests/*"},
			expectedMatched: true,
			expectedPattern: "tests/*",
		},
		{
			name:            "does not use prefix matching for plain paths",
			scanRoot:        "project",
			path:            "project/tests/unit/package-lock.json",
			cliExcludePaths: []string{"tests"},
			expectedMatched: false,
			expectedPattern: "",
		},
		{
			name:            "invalid pattern returns error",
			scanRoot:        "project",
			path:            "project/file.txt",
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

			matched, pattern, err := matchConfigExclusion(tt.repoRoot, tt.path, tt.configExcludePaths, mockReporter)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedMatched, matched)
			assert.Equal(t, tt.expectedPattern, pattern)
		})
	}
}
