package fileposition

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestRemoveHostPath(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	scanPath := "."
	packagePath := filepath.FromSlash(filepath.Join(dir, "path_test.go"))

	assert.Equal(t, "path_test.go", ToRelativePath(scanPath, packagePath))
}

func TestShouldExcludePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		dir             string
		path            string
		excludePaths    []string
		expected        bool
		expectedPattern string
		expectError     bool
	}{
		{
			name:            "Path matches exclusion pattern",
			dir:             "project",
			path:            filepath.Join("project", "file.txt"),
			excludePaths:    []string{"*.txt"},
			expected:        true,
			expectedPattern: "*.txt",
			expectError:     false,
		},
		{
			name:            "Path matches one of several exclusion pattern",
			dir:             "project",
			path:            filepath.Join("project", "file.txt"),
			excludePaths:    []string{"*.go", "*.md", "*.txt"},
			expected:        true,
			expectedPattern: "*.txt",
			expectError:     false,
		},
		{
			name:            "Path does not match exclusion pattern",
			dir:             "project",
			path:            filepath.Join("project", "file.go"),
			excludePaths:    []string{"*.txt"},
			expected:        false,
			expectedPattern: "",
			expectError:     false,
		},
		{
			name:            "Invalid exclusion pattern",
			dir:             "project",
			path:            filepath.Join("project", "file.go"),
			excludePaths:    []string{"["},
			expected:        false,
			expectedPattern: "",
			expectError:     true,
		},
		{
			name:            "Non-relative path",
			dir:             "different-project",
			path:            filepath.Join("project", "file.txt"),
			excludePaths:    []string{"*.go"},
			expected:        false,
			expectedPattern: "",
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, pattern, err := ShouldExcludePath(tt.dir, tt.path, tt.excludePaths)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.expectedPattern, pattern)
		})
	}
}
