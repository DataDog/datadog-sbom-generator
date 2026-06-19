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

func TestParseGradleSettingsProjectName_IncludeWithoutLeadingColon(t *testing.T) {
	t.Parallel()

	// Gradle supports include 'app' (without leading colon) as well as include ':app'.
	root := t.TempDir()
	subA := filepath.Join(root, "communication")
	subB := filepath.Join(root, "lib-core")
	require.NoError(t, os.Mkdir(subA, 0700))
	require.NoError(t, os.Mkdir(subB, 0700))
	settings := "include 'communication'\ninclude 'lib-core'\nproject(':lib-core').name = 'comms-core'\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte(settings), 0600))

	assert.Equal(t, "communication", parseGradleSettingsProjectName(root, subA))
	// Name override still applies when the include is colon-less.
	assert.Equal(t, "comms-core", parseGradleSettingsProjectName(root, subB))
}

func TestParseGradleSettingsProjectName_IncludeBuildNotMatchedAsSubproject(t *testing.T) {
	t.Parallel()

	// includeBuild, includeFlat, etc. must not be treated as include statements.
	root := t.TempDir()
	subDir := filepath.Join(root, "lib")
	require.NoError(t, os.Mkdir(subDir, 0700))
	settings := "includeBuild '../lib'\nincludeFlat 'sibling'\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle"), []byte(settings), 0600))

	assert.Equal(t, "", parseGradleSettingsProjectName(root, subDir))
}

func TestStripGradleComments_SingleLineComment(t *testing.T) {
	t.Parallel()

	// The space before '//' is preserved; only the comment text is blanked.
	src := []byte("group = 'com.example' // this is the group\n")
	got := string(stripGradleComments(src))
	assert.Equal(t, "group = 'com.example'                     \n", got)
}

func TestStripGradleComments_BlockComment(t *testing.T) {
	t.Parallel()

	// '/* block */' (11 chars) + trailing space = 12 blanked positions before 'group'.
	src := []byte("/* block */ group = 'x'\n")
	got := string(stripGradleComments(src))
	assert.Equal(t, "            group = 'x'\n", got)
}

func TestStripGradleComments_PreservesURLsInStrings(t *testing.T) {
	t.Parallel()

	// '//' inside a quoted string must not be treated as a comment delimiter;
	// the closing brace on the same line must be preserved so brace-counting works.
	src := []byte(`repositories { maven { url = uri("https://repo.example.com") } }` + "\n")
	got := stripGradleComments(src)
	assert.Equal(t, src, got, "string containing // should be left untouched")
}

func TestStripGradleComments_BlockCommentPreservesNewlines(t *testing.T) {
	t.Parallel()

	src := []byte("/* line1\nline2 */group = 'x'\n")
	got := string(stripGradleComments(src))
	// Newlines inside the block comment must be preserved so line numbers stay aligned.
	assert.Contains(t, got, "\n")
	assert.Contains(t, got, "group = 'x'")
}

func TestExtractGroupFromRootBuildFile_TopLevel_NotInherited(t *testing.T) {
	t.Parallel()

	// A top-level `group = 'x'` in the root build file only applies to the root
	// project in Gradle, not to subprojects. extractGroupFromRootBuildFile must
	// not return it, to avoid incorrectly assigning it to ungrouped subprojects.
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle"), []byte("group = 'com.example'\n"), 0600))

	assert.Equal(t, "", extractGroupFromRootBuildFile(root))
}

func TestExtractGroupFromRootBuildFile_AllprojectsBlock(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := "allprojects {\n  group = 'com.datadoghq'\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle"), []byte(content), 0600))

	assert.Equal(t, "com.datadoghq", extractGroupFromRootBuildFile(root))
}

func TestExtractGroupFromRootBuildFile_KotlinDSL_AllprojectsBlock(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := "allprojects {\n    group = \"com.example.kts\"\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle.kts"), []byte(content), 0600))

	assert.Equal(t, "com.example.kts", extractGroupFromRootBuildFile(root))
}

func TestExtractGroupFromRootBuildFile_NoBuildFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	assert.Equal(t, "", extractGroupFromRootBuildFile(root))
}

func TestExtractGroupFromRootBuildFile_EmptyRootDir(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "", extractGroupFromRootBuildFile(""))
}

func TestExtractGroupFromRootBuildFile_TopLevelAfterBlock_NotInherited(t *testing.T) {
	t.Parallel()

	// A top-level `group = 'com.root'` that appears AFTER an allprojects block must
	// not be captured. The brace-counting approach ensures the search is bounded to
	// the block body and does not spill beyond the closing `}`.
	root := t.TempDir()
	content := "allprojects {\n  repositories {\n    mavenCentral()\n  }\n}\ngroup = 'com.root'\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle"), []byte(content), 0600))

	assert.Equal(t, "", extractGroupFromRootBuildFile(root))
}

func TestExtractGroupFromRootBuildFile_GroupAfterNestedBlock(t *testing.T) {
	t.Parallel()

	// group = '...' that appears after a nested repositories {} block inside
	// allprojects is a common Gradle pattern and must be found correctly.
	root := t.TempDir()
	content := "allprojects {\n  repositories {\n    mavenCentral()\n  }\n  group = 'com.datadoghq'\n}\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build.gradle"), []byte(content), 0600))

	assert.Equal(t, "com.datadoghq", extractGroupFromRootBuildFile(root))
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

func TestParseGradleSettingsProjectName_MultilineInclude_SingleItem(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subDir := filepath.Join(root, "subA")
	require.NoError(t, os.Mkdir(subDir, 0700))
	// A single-item multiline include is supported: \s* in the regex crosses the
	// line boundary between include( and the quoted path on the next line.
	settings := "include(\n  \":subA\"\n)\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle.kts"), []byte(settings), 0600))

	assert.Equal(t, "subA", parseGradleSettingsProjectName(root, subDir))
}

func TestParseGradleSettingsProjectName_MultilineInclude_MultiItem_NotSupported(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	subA := filepath.Join(root, "subA")
	subB := filepath.Join(root, "subB")
	require.NoError(t, os.MkdirAll(subA, 0700))
	require.NoError(t, os.MkdirAll(subB, 0700))
	// Multi-item multiline include is NOT fully supported: only the first item on the
	// matched line is captured; subsequent items on separate lines are missed.
	// The call site falls back to the directory basename for unresolved projects.
	settings := "include(\n  \":subA\",\n  \":subB\"\n)\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "settings.gradle.kts"), []byte(settings), 0600))

	// subA is found (first item captured by the regex match).
	assert.Equal(t, "subA", parseGradleSettingsProjectName(root, subA))
	// subB is NOT found — falls back to "" at this layer; call site uses dir basename.
	assert.Equal(t, "", parseGradleSettingsProjectName(root, subB))
}
