package ruby_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/ruby"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time check: GemfileLockExtractor must implement ArtifactExtractor.
var _ extractor.ArtifactExtractor = ruby.GemfileLockExtractor{}

func TestGemfileLockExtractor_GetArtifact_PathDirectives(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	// app/Gemfile.lock + app/Gemfile with path: directives
	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	lockfilePath := filepath.Join(appDir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n\nDEPENDENCIES\n"), 0600))

	gemfilePath := filepath.Join(appDir, "Gemfile")
	require.NoError(t, os.WriteFile(gemfilePath, []byte(`source "https://rubygems.org"

gem 'core', path: '../core'
gem 'utils', path: 'libs/utils'
gem 'rails', '~> 7.0'
`), 0600))

	// Create target Gemfiles
	coreDir := filepath.Join(root, "core")
	require.NoError(t, os.MkdirAll(coreDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(coreDir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	utilsDir := filepath.Join(appDir, "libs", "utils")
	require.NoError(t, os.MkdirAll(utilsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(utilsDir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, gemfilePath, artifact.Filename)
	assert.Equal(t, models.EcosystemRubyGems, artifact.Ecosystem)
	require.Len(t, artifact.ProjectDeps, 2)

	// Collect filenames for order-independent comparison
	depFiles := make([]string, len(artifact.ProjectDeps))
	for i, dep := range artifact.ProjectDeps {
		depFiles[i] = dep.Filename
	}
	assert.Contains(t, depFiles, filepath.Join(coreDir, "Gemfile"))
	assert.Contains(t, depFiles, filepath.Join(utilsDir, "Gemfile"))
}

func TestGemfileLockExtractor_GetArtifact_MissingTargetSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	gemfilePath := filepath.Join(dir, "Gemfile")
	require.NoError(t, os.WriteFile(gemfilePath, []byte(`gem 'missing_lib', path: '../nonexistent'
`), 0600))

	// ../nonexistent/Gemfile does NOT exist

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "missing target Gemfile should be silently skipped")
}

func TestGemfileLockExtractor_GetArtifact_Deduplication(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	lockfilePath := filepath.Join(appDir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	gemfilePath := filepath.Join(appDir, "Gemfile")
	require.NoError(t, os.WriteFile(gemfilePath, []byte(`gem 'lib_a', path: '../shared'
gem 'lib_b', path: '../shared'
`), 0600))

	sharedDir := filepath.Join(root, "shared")
	require.NoError(t, os.MkdirAll(sharedDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sharedDir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Len(t, artifact.ProjectDeps, 1, "duplicate path targets should be deduplicated")
}

func TestGemfileLockExtractor_GetArtifact_OutsideScanRoot(t *testing.T) {
	t.Parallel()

	repo := t.TempDir()

	scanRoot := filepath.Join(repo, "scanRoot")
	appDir := filepath.Join(scanRoot, "app")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	lockfilePath := filepath.Join(appDir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	gemfilePath := filepath.Join(appDir, "Gemfile")
	require.NoError(t, os.WriteFile(gemfilePath, []byte(`gem 'outside_lib', path: '../../outside'
`), 0600))

	// Target exists but outside scanRoot
	outsideDir := filepath.Join(repo, "outside")
	require.NoError(t, os.MkdirAll(outsideDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	ctx := extractor.ScanContext{RootDir: scanRoot}
	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, ctx)
	require.NoError(t, err)
	require.NotNil(t, artifact)
	assert.Empty(t, artifact.ProjectDeps, "target outside scan root must be skipped")
}

func TestGemfileLockExtractor_GetArtifact_NoGemfile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	// No Gemfile exists

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	assert.Nil(t, artifact, "no adjacent Gemfile means no artifact should be emitted")
}

func TestGemfileLockExtractor_GetArtifact_PathInGroup(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	appDir := filepath.Join(root, "app")
	require.NoError(t, os.MkdirAll(appDir, 0755))

	lockfilePath := filepath.Join(appDir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	gemfilePath := filepath.Join(appDir, "Gemfile")
	require.NoError(t, os.WriteFile(gemfilePath, []byte(`source "https://rubygems.org"

group :development do
  gem 'dev_tools', path: '../dev_tools'
end
`), 0600))

	devToolsDir := filepath.Join(root, "dev_tools")
	require.NoError(t, os.MkdirAll(devToolsDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(devToolsDir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	require.Len(t, artifact.ProjectDeps, 1, "path: inside group block should be captured")
	assert.Equal(t, filepath.Join(devToolsDir, "Gemfile"), artifact.ProjectDeps[0].Filename)
}

func TestGemfileLockExtractor_GetArtifact_GemspecName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "my_service.gemspec"), []byte(`Gem::Specification.new do |spec|
  spec.name    = "my_service"
  spec.version = "1.0.0"
end
`), 0600))

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Equal(t, "my_service", artifact.Name, "gem name should be extracted from adjacent .gemspec")
}

func TestGemfileLockExtractor_GetArtifact_NoGemspecName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	lockfilePath := filepath.Join(dir, "Gemfile.lock")
	require.NoError(t, os.WriteFile(lockfilePath, []byte("GEM\n  specs:\n"), 0600))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile"), []byte("source \"https://rubygems.org\"\n"), 0600))

	// No .gemspec present

	f, err := extractor.OpenLocalDepFile(lockfilePath)
	require.NoError(t, err)
	defer f.Close()

	artifact, err := ruby.GemfileLockExtractor{}.GetArtifact(f, extractor.ScanContext{})
	require.NoError(t, err)
	require.NotNil(t, artifact)

	assert.Empty(t, artifact.Name, "Name should be empty when no .gemspec is present")
}
