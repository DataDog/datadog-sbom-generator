package config

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/models"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestFetchExclusionsUsesLocalConfigWithoutAuth(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	t.Setenv("DD_JWT_TOKEN", "")
	t.Setenv("DATADOG_API_KEY", "")
	t.Setenv("DATADOG_APP_KEY", "")
	t.Setenv("DATADOG_JWT_TOKEN", "")

	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	localConfig := "schema-version: v1.7\nsca:\n  ignore-paths:\n    - vendor/**\n  ignore-ecosystems:\n    - npm\n  ignore-packages:\n    - Go:golang.org/x/text\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(localConfig), testFilePerms))

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] No Datadog authentication available, using local configuration only\n").Times(1)
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()

	exclusions, repoRoot, err := FetchExclusions(dir, "", "", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, []string{"vendor/**"}, exclusions.Paths)
	assert.Equal(t, []string{"npm"}, exclusions.Ecosystems)
	assert.Equal(t, []string{"Go:golang.org/x/text"}, exclusions.Packages)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsUsesMergedConfigWhenAuthAndRepositoryPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: remoteName,
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	require.NoError(t, err)

	localConfig := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - vendor/**\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(localConfig), testFilePerms))

	mergedConfig := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - contracts/**\n    - test/**\n"
	encodedMergedConfig := base64.StdEncoding.EncodeToString([]byte(mergedConfig))
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`{
			"data": {
				"id": "bf23e8eb-3e49-4b4b-8612-cde1c5e62a5b",
				"type": "config",
				"attributes": {
					"config_base64": "%s"
				}
			}
		}`, encodedMergedConfig)))
	}))
	defer mockServer.Close()

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] Fetching merged configuration for %s\n", "https://github.com/DataDog/example-repo").Times(1)
	mockReporter.EXPECT().Warnf(gomock.Any(), gomock.Any()).AnyTimes()

	exclusions, repoRoot, err := FetchExclusions(dir, mockServer.URL, "jwt-token", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, []string{"contracts/**", "test/**"}, exclusions.Paths)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsFallsBackToLocalConfigWhenMergedFetchFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: remoteName,
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	require.NoError(t, err)

	localConfig := "schema-version: v1.1\nsca:\n  ignore-paths:\n    - vendor/**\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(localConfig), testFilePerms))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockServer.Close()

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] Fetching merged configuration for %s\n", "https://github.com/DataDog/example-repo").Times(1)
	mockReporter.EXPECT().Warnf("[config] Failed to fetch merged configuration, continuing with local configuration: %v\n", gomock.Any()).Times(1)

	exclusions, repoRoot, err := FetchExclusions(dir, mockServer.URL, "jwt-token", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, []string{"vendor/**"}, exclusions.Paths)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsReturnsAPIFailedWhenExitOnFetchFailureIsEnabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	_, err = repo.CreateRemote(&gitconfig.RemoteConfig{
		Name: remoteName,
		URLs: []string{"https://github.com/DataDog/example-repo"},
	})
	require.NoError(t, err)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer mockServer.Close()

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] Fetching merged configuration for %s\n", "https://github.com/DataDog/example-repo").Times(1)

	exclusions, repoRoot, err := FetchExclusions(dir, mockServer.URL, "jwt-token", true, mockReporter)
	require.ErrorIs(t, err, models.ErrAPIFailed)
	assert.Equal(t, Exclusions{}, exclusions)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsWarnsAndSkipsMalformedLocalConfig(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	t.Setenv("DD_JWT_TOKEN", "")
	t.Setenv("DATADOG_API_KEY", "")
	t.Setenv("DATADOG_APP_KEY", "")
	t.Setenv("DATADOG_JWT_TOKEN", "")

	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(":\n  invalid: [yaml\n"), testFilePerms))

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] No Datadog authentication available, using local configuration only\n").Times(1)
	mockReporter.EXPECT().Warnf("[config] Failed to parse configuration: %v\n", gomock.Any()).Times(1)

	exclusions, repoRoot, err := FetchExclusions(dir, "", "", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, Exclusions{}, exclusions)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsWarnsOnUnknownIgnoreEcosystem(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	t.Setenv("DD_JWT_TOKEN", "")
	t.Setenv("DATADOG_API_KEY", "")
	t.Setenv("DATADOG_APP_KEY", "")
	t.Setenv("DATADOG_JWT_TOKEN", "")

	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	localConfig := "schema-version: v1.7\nsca:\n  ignore-ecosystems:\n    - npm\n    - NPM\n    - not-a-real-ecosystem\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(localConfig), testFilePerms))

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] No Datadog authentication available, using local configuration only\n").Times(1)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q does not match any known ecosystem (check spelling and case) and will never match\n", "config", "sca.ignore-ecosystems", "NPM").Times(1)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q does not match any known ecosystem (check spelling and case) and will never match\n", "config", "sca.ignore-ecosystems", "not-a-real-ecosystem").Times(1)

	exclusions, repoRoot, err := FetchExclusions(dir, "", "", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm", "NPM", "not-a-real-ecosystem"}, exclusions.Ecosystems)
	assert.Equal(t, dir, repoRoot)
}

func TestFetchExclusionsWarnsOnMalformedOrUnknownIgnorePackage(t *testing.T) {
	t.Setenv("DD_API_KEY", "")
	t.Setenv("DD_APP_KEY", "")
	t.Setenv("DD_JWT_TOKEN", "")
	t.Setenv("DATADOG_API_KEY", "")
	t.Setenv("DATADOG_APP_KEY", "")
	t.Setenv("DATADOG_JWT_TOKEN", "")

	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	localConfig := "schema-version: v1.7\nsca:\n  ignore-packages:\n    - npm:lodash\n    - lodash\n    - NPM:lodash\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(localConfig), testFilePerms))

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Infof("[config] No Datadog authentication available, using local configuration only\n").Times(1)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q is missing the \"<ecosystem>:<name>\" separator and will never match\n", "config", "sca.ignore-packages", "lodash").Times(1)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q does not match any known ecosystem (check spelling and case) and will never match\n", "config", "sca.ignore-packages", "NPM:lodash").Times(1)

	exclusions, repoRoot, err := FetchExclusions(dir, "", "", false, mockReporter)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm:lodash", "lodash", "NPM:lodash"}, exclusions.Packages)
	assert.Equal(t, dir, repoRoot)
}

func TestValidateEcosystemExclusionsWarnsOnUnknownEcosystem(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q does not match any known ecosystem (check spelling and case) and will never match\n", "cli", "--exclude-ecosystem", "NPM").Times(1)

	ValidateEcosystemExclusions("cli", "--exclude-ecosystem", []string{"npm", "NPM"}, mockReporter)
}

func TestValidatePackageExclusionsWarnsOnMalformedOrUnknownPackage(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockReporter := reporter.NewMockReporter(ctrl)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q is missing the \"<ecosystem>:<name>\" separator and will never match\n", "cli", "--exclude-package", "lodash").Times(1)
	mockReporter.EXPECT().Warnf("[%s] %s entry %q does not match any known ecosystem (check spelling and case) and will never match\n", "cli", "--exclude-package", "NPM:lodash").Times(1)

	ValidatePackageExclusions("cli", "--exclude-package", []string{"npm:lodash", "lodash", "NPM:lodash"}, mockReporter)
}
