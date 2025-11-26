package python_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestPoetryLockExtractor_ShouldExtract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "",
			path: "",
			want: false,
		},
		{
			name: "",
			path: "poetry.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/poetry.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.poetry.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := python.PoetryLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePoetryLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePoetryLock("../fixtures/poetry/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_InvalidToml(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePoetryLock("../fixtures/poetry/not-toml.txt")

	testutil.ExpectErrContaining(t, err, "could not extract from")
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := python.ParsePoetryLock("../fixtures/poetry/empty.lock")

	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{})
}

func TestParsePoetryLock_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/one-package.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			Version:        "1.23.3",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
		},
	})
}

//nolint:paralleltest
func TestParsePoetryLock_OnePackage_MatcherFailed(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	stderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	os.Stderr = w

	// Mock pyprojectTOMLMatcher to fail
	matcherError := errors.New("pyprojectTOMLMatcher failed")
	python.PoetryExtractor.Matchers = []lockfile.Matcher{testutil.FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/one-package.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Capture stderr
	_ = w.Close()
	os.Stderr = stderr
	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, r)
	if err != nil {
		t.Errorf("failed to copy stderr output: %v", err)
	}
	_ = r.Close()

	assert.Contains(t, buffer.String(), matcherError.Error())
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			Version:        "1.23.3",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
		},
	})

	// Reset pyprojectTOMLMatcher mock
	testutil.MockAllMatchers()
}

func TestParsePoetryLock_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/two-packages.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "proto-plus",
			Version:        "1.22.0",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
		},
		{
			Name:           "protobuf",
			Version:        "4.21.5",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
		},
	})
}

func TestParsePoetryLock_PackageWithMetadata(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/one-package-with-metadata.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "emoji",
			Version:        "2.0.0",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
		},
	})
}

func TestParsePoetryLock_PackageWithGitSource(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/source-git.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "ike",
			Version:        "0.2.0",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
			Commit:         "cd66602cd29f61a2d2e7fb995fef1e61708c034d",
		},
	})
}

func TestParsePoetryLock_PackageWithLegacySource(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/source-legacy.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "appdirs",
			Version:        "1.4.4",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
			Commit:         "",
		},
	})
}

func TestParsePoetryLock_OptionalPackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/poetry/optional-package.lock"))
	packages, err := python.ParsePoetryLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "numpy",
			Version:        "1.23.3",
			PackageManager: models.Poetry,
			Ecosystem:      models.EcosystemPyPI,
			DepGroups:      []string{"optional"},
		},
	})
}
