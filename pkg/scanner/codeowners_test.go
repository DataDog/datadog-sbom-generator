package scanner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/internal/thirdparty/codeowners"
	"github.com/DataDog/datadog-sbom-generator/pkg/reporter"
	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveCodeownerTeams(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		rules string
		file  string
		teams []string
	}{
		{"teams only, sorted and deduplicated", "* @org/z @person person@example.com @org/a @org/z", "go.mod", []string{"org/a", "org/z"}},
		{"ownerless override", "* @org/team\n/payments/", "payments/go.mod", []string{}},
		{"no matching rule", "/payments/ @org/team", "go.mod", []string{}},
		{"comma", "/a,b/ @org/team", "a,b/go.mod", []string{"org/team"}},
		{"brackets", "/app/[id]/ @org/team", "app/[id]/package.json", []string{"org/team"}},
		{"root slash does not match files", "* @org/team\n/ @org/root", "go.mod", []string{"org/team"}},
		{"windows input", "/payments/ @org/team", `payments\go.mod`, []string{"org/team"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rules, err := codeowners.ParseFile(strings.NewReader(tc.rules))
			require.NoError(t, err)
			teams, err := resolveCodeownerTeams(rules, tc.file)
			require.NoError(t, err)
			assert.Equal(t, tc.teams, teams)
		})
	}
}

func TestLoadCodeownerRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		files   map[string]string
		teams   []string
		wantErr bool
	}{
		{"missing", nil, []string{}, false},
		{"github takes precedence", map[string]string{
			".github/CODEOWNERS": "* @org/github",
			"CODEOWNERS":         "* @org/root",
			"docs/CODEOWNERS":    "* @org/docs",
		}, []string{"org/github"}, false},
		{"root takes precedence over docs", map[string]string{
			"CODEOWNERS":      "* @org/root",
			"docs/CODEOWNERS": "* @org/docs",
		}, []string{"org/root"}, false},
		{"docs fallback", map[string]string{"docs/CODEOWNERS": "* @org/docs"}, []string{"org/docs"}, false},
		{"invalid file blocks fallback", map[string]string{
			".github/CODEOWNERS": "* !invalid",
			"CODEOWNERS":         "* @org/root",
		}, nil, true},
		{"truncated file is rejected", map[string]string{
			"CODEOWNERS": "* @org/team\n" + strings.Repeat("x", 70_000),
		}, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := codeownersTestRepository(t, tc.files)
			rules, err := loadCodeownerRules(root)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			teams, err := resolveCodeownerTeams(rules, "go.mod")
			require.NoError(t, err)
			assert.Equal(t, tc.teams, teams)
		})
	}
}

func TestCodeownerSymlinksDoNotEscapeOrFallThrough(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}

	for _, target := range []string{"outside", "missing"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()
			root := codeownersTestRepository(t, map[string]string{"CODEOWNERS": "* @org/fallback"})
			require.NoError(t, os.Mkdir(filepath.Join(root, ".github"), 0700))
			external := filepath.Join(t.TempDir(), "CODEOWNERS")
			if target == "outside" {
				require.NoError(t, os.WriteFile(external, []byte("* @org/outside"), 0600))
			}
			require.NoError(t, os.Symlink(external, filepath.Join(root, ".github", "CODEOWNERS")))
			_, err := loadRepositoryCodeowners(root)
			require.Error(t, err)
		})
	}
}

func TestCodeownerUnreadableInputIsUnavailable(t *testing.T) {
	t.Parallel()
	root := codeownersTestRepository(t, nil)
	require.NoError(t, os.Mkdir(filepath.Join(root, "CODEOWNERS"), 0700))
	_, err := loadRepositoryCodeowners(root)
	require.Error(t, err)
}

func TestCodeownerAncestorSymlinkDoesNotFallThrough(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires additional privileges on Windows")
	}
	for _, tc := range []struct {
		name   string
		exists bool
	}{
		{"dangling parent", false},
		{"external parent", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := codeownersTestRepository(t, map[string]string{"CODEOWNERS": "* @org/fallback"})
			outside := filepath.Join(t.TempDir(), "github")
			if tc.exists {
				require.NoError(t, os.Mkdir(outside, 0700))
			}
			require.NoError(t, os.Symlink(outside, filepath.Join(root, ".github")))
			_, err := loadRepositoryCodeowners(root)
			require.Error(t, err)
		})
	}
}

func TestCodeownerFailureWarnsAtDefaultVerbosity(t *testing.T) {
	t.Parallel()
	root := codeownersTestRepository(t, map[string]string{
		"CODEOWNERS": "* !invalid", "package-lock.json": packageJSONLock,
	})
	var stderr bytes.Buffer
	r := reporter.NewJSONReporter(io.Discard, &stderr, reporter.ErrorLevel)
	results, err := DoScan(ScannerActions{
		DirectoryPaths: []string{root}, Recursive: true, ResolveCodeowners: true,
	}, r)
	require.NoError(t, err)
	require.NotEmpty(t, results.Results)
	assert.Contains(t, stderr.String(), "[codeowners] Ownership unavailable")
	assert.False(t, r.HasErrored())
}

func TestScanCodeownerPresenceAndSubdirectoryPaths(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		enabled bool
		rules   string
		absent  bool
		teams   []string
	}{
		{"disabled", false, "* @org/team", true, nil},
		{"owned", true, "/payments/ @org/payments", false, []string{"org/payments"}},
		{"computed unowned", true, "* @org/team\n/payments/", false, []string{}},
		{"invalid", true, "* !invalid", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := codeownersTestRepository(t, map[string]string{
				".github/CODEOWNERS":         tc.rules,
				"payments/package-lock.json": packageJSONLock,
			})
			results, err := DoScan(ScannerActions{
				DirectoryPaths:    []string{filepath.Join(root, "payments")},
				Recursive:         true,
				ResolveCodeowners: tc.enabled,
			}, &reporter.VoidReporter{})
			require.NoError(t, err)
			require.Len(t, results.Results, 1)
			require.NotEmpty(t, results.Results[0].Packages)
			for _, pkg := range results.Results[0].Packages {
				require.NotEmpty(t, pkg.Locations)
				for _, location := range pkg.Locations {
					assert.Equal(t, "package-lock.json", location.Block.Filename)
					if tc.absent {
						assert.Nil(t, location.Codeowners)
					} else {
						require.NotNil(t, location.Codeowners)
						assert.Equal(t, tc.teams, *location.Codeowners)
					}
				}
			}
		})
	}
}

func TestScanCodeownersUsesEachRepository(t *testing.T) {
	t.Parallel()
	first := codeownersTestRepository(t, map[string]string{
		"CODEOWNERS": "* @org/first", "package-lock.json": packageJSONLock,
	})
	second := codeownersTestRepository(t, map[string]string{
		"CODEOWNERS": "* @org/second", "yarn.lock": yarnLock,
	})
	results, err := DoScan(ScannerActions{
		DirectoryPaths: []string{first, second}, Recursive: true, ResolveCodeowners: true,
	}, &reporter.VoidReporter{})
	require.NoError(t, err)
	require.Len(t, results.Results, 2)
	teamsByFile := map[string][]string{}
	for _, source := range results.Results {
		for _, pkg := range source.Packages {
			for _, location := range pkg.Locations {
				require.NotNil(t, location.Codeowners)
				teamsByFile[location.Block.Filename] = *location.Codeowners
			}
		}
	}
	assert.Equal(t, map[string][]string{"package-lock.json": {"org/first"}, "yarn.lock": {"org/second"}}, teamsByFile)
}

func codeownersTestRepository(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	_, err := git.PlainInit(root, false)
	require.NoError(t, err)
	for path, content := range files {
		fullPath := filepath.Join(root, filepath.FromSlash(path))
		require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0700))
		require.NoError(t, os.WriteFile(fullPath, []byte(content), 0600))
	}

	return root
}
