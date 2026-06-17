package java

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGradleSettingsProjectName_RootProjectSingleQuotes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte("rootProject.name = 'my-app'\n"), 0600))

	name := parseGradleSettingsProjectName(root, root)
	assert.Equal(t, "my-app", name)
}

func TestParseGradleSettingsProjectName_RootProjectDoubleQuotes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte(`rootProject.name = "my-app"`+"\n"), 0600))

	name := parseGradleSettingsProjectName(root, root)
	assert.Equal(t, "my-app", name)
}

func TestParseGradleSettingsProjectName_SubprojectFromInclude(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "subA")
	require.NoError(t, os.Mkdir(subDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte("include ':subA'\n"), 0600))

	name := parseGradleSettingsProjectName(root, subDir)
	assert.Equal(t, "subA", name)
}

func TestParseGradleSettingsProjectName_SubprojectNameOverride(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "subA")
	require.NoError(t, os.Mkdir(subDir, 0700))
	settings := "include ':subA'\nproject(':subA').name = 'renamed'\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte(settings), 0600))

	name := parseGradleSettingsProjectName(root, subDir)
	assert.Equal(t, "renamed", name)
}

func TestParseGradleSettingsProjectName_KotlinDSL(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "subA")
	require.NoError(t, os.Mkdir(subDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle.kts"), []byte("include(\":subA\")\n"), 0600))

	name := parseGradleSettingsProjectName(root, subDir)
	assert.Equal(t, "subA", name)
}

func TestParseGradleSettingsProjectName_MultipleIncludes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subA := filepath.Join(root, "subA")
	subB := filepath.Join(root, "subB")
	require.NoError(t, os.Mkdir(subA, 0700))
	require.NoError(t, os.Mkdir(subB, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte("include ':subA', ':subB'\n"), 0600))

	assert.Equal(t, "subA", parseGradleSettingsProjectName(root, subA))
	assert.Equal(t, "subB", parseGradleSettingsProjectName(root, subB))
}

func TestParseGradleSettingsProjectName_NestedSubproject(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nested := filepath.Join(root, "sub", "module")
	require.NoError(t, os.MkdirAll(nested, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte("include ':sub:module'\n"), 0600))

	name := parseGradleSettingsProjectName(root, nested)
	assert.Equal(t, "module", name)
}

func TestParseGradleSettingsProjectName_NoSettingsFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	name := parseGradleSettingsProjectName(root, root)
	assert.Equal(t, "", name)
}

func TestParseGradleSettingsProjectName_ProjectNotInSettings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "unknown")
	require.NoError(t, os.Mkdir(subDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte("include ':other'\n"), 0600))

	name := parseGradleSettingsProjectName(root, subDir)
	assert.Equal(t, "", name)
}

func TestParseGradleSettingsProjectName_EmptyRootDir(t *testing.T) {
	t.Parallel()

	name := parseGradleSettingsProjectName("", "/some/path")
	assert.Equal(t, "", name)
}

func TestParseGradleSettingsProjectName_KotlinDSLNameOverride(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "subA")
	require.NoError(t, os.Mkdir(subDir, 0700))
	settings := "include(\":subA\")\nproject(\":subA\").name = \"renamed-kts\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle.kts"), []byte(settings), 0600))

	name := parseGradleSettingsProjectName(root, subDir)
	assert.Equal(t, "renamed-kts", name)
}
