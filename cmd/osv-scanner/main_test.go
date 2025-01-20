// main cannot be accessed directly, so cannot use main_test
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/datadog/datadog-sbom-generator/internal/cachedregexp"
	"github.com/datadog/datadog-sbom-generator/internal/testutility"
	"github.com/urfave/cli/v2"
)

type cliTestCase struct {
	name string
	args []string
	exit int
}

type locationTestCase struct {
	name          string
	args          []string
	wantExitCode  int
	wantFilePaths []string
}

type encodingTestCase struct {
	encoding string
}

// Attempts to normalize any file paths in the given `output` so that they can
// be compared reliably regardless of the file path separator being used.
//
// Namely, escaped forward slashes are replaced with backslashes.
func normalizeFilePaths(t *testing.T, output string) string {
	t.Helper()

	return strings.ReplaceAll(strings.ReplaceAll(output, "\\\\", "/"), "\\", "/")
}

// normalizeRootDirectory attempts to replace references to the current working
// directory with "<rootdir>", in order to reduce the noise of the cmp diff
func normalizeRootDirectory(t *testing.T, str string) string {
	t.Helper()

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("could not get cwd (%v) - results and diff might be inaccurate!", err)
	}

	cwd = normalizeFilePaths(t, cwd)

	// file uris with Windows end up with three slashes, so we normalize that too
	str = strings.ReplaceAll(str, "file:///"+cwd, "file://<rootdir>")

	return strings.ReplaceAll(str, cwd, "<rootdir>")
}

// normalizeUserCacheDirectory attempts to replace references to the current working
// directory with "<tempdir>", in order to reduce the noise of the cmp diff
func normalizeUserCacheDirectory(t *testing.T, str string) string {
	t.Helper()

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		t.Errorf("could not get user cache (%v) - results and diff might be inaccurate!", err)
	}

	cacheDir = normalizeFilePaths(t, cacheDir)

	// file uris with Windows end up with three slashes, so we normalize that too
	str = strings.ReplaceAll(str, "file:///"+cacheDir, "file://<tempdir>")

	return strings.ReplaceAll(str, cacheDir, "<tempdir>")
}

// normalizeTempDirectory attempts to replace references to the temp directory
// with "<tempdir>", to ensure tests pass across different OSs
func normalizeTempDirectory(t *testing.T, str string) string {
	t.Helper()

	//nolint:gocritic // ensure that the directory doesn't end with a trailing slash
	tempDir := normalizeFilePaths(t, filepath.Join(os.TempDir()))
	re := cachedregexp.MustCompile(tempDir + `/osv-scanner-test-\d+`)

	return re.ReplaceAllString(str, "<tempdir>")
}

// normalizeErrors attempts to replace error messages on alternative OSs with their
// known linux equivalents, to ensure tests pass across different OSs
func normalizeErrors(t *testing.T, str string) string {
	t.Helper()

	str = strings.ReplaceAll(str, "The filename, directory name, or volume label syntax is incorrect.", "no such file or directory")
	str = strings.ReplaceAll(str, "The system cannot find the path specified.", "no such file or directory")
	str = strings.ReplaceAll(str, "The system cannot find the file specified.", "no such file or directory")

	return str
}

// normalizeStdStream applies a series of normalizes to the buffer from a std stream like stdout and stderr
func normalizeStdStream(t *testing.T, std *bytes.Buffer) string {
	t.Helper()

	str := std.String()

	for _, normalizer := range []func(t *testing.T, str string) string{
		normalizeFilePaths,
		normalizeRootDirectory,
		normalizeTempDirectory,
		normalizeUserCacheDirectory,
		normalizeErrors,
	} {
		str = normalizer(t, str)
	}

	return str
}

func runCli(t *testing.T, tc cliTestCase) (string, string) {
	t.Helper()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	ec := run(tc.args, stdout, stderr)

	if ec != tc.exit {
		t.Errorf("cli exited with code %d, not %d", ec, tc.exit)
	}

	return normalizeStdStream(t, stdout), normalizeStdStream(t, stderr)
}

func testCli(t *testing.T, tc cliTestCase) {
	t.Helper()

	stdout, stderr := runCli(t, tc)

	testutility.NewSnapshot().MatchText(t, stdout)
	testutility.NewSnapshot().MatchText(t, stderr)
}

func TestRun(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name: "",
			args: []string{""},
			exit: 0,
		},
		{
			name: "",
			args: []string{"", "--version"},
			exit: 0,
		},
		// one specific supported lockfile
		{
			name: "one specific supported lockfile",
			args: []string{"", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// one specific supported sbom with vulns
		{
			name: "folder of supported sbom with vulns",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "./fixtures/sbom-insecure/"},
			exit: 0,
		},
		// one specific supported sbom with vulns
		{
			name: "one specific supported sbom with vulns",
			args: []string{"", "--config=./fixtures/osv-scanner-empty-config.toml", "--sbom", "./fixtures/sbom-insecure/alpine.cdx.xml"},
			exit: 0,
		},
		// one specific unsupported lockfile
		{
			name: "",
			args: []string{"", "./fixtures/locks-many/not-a-lockfile.toml"},
			exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "Scan locks-many",
			args: []string{"", "./fixtures/locks-many"},
			exit: 0,
		},
		// all supported lockfiles in the directory should be checked
		{
			name: "all supported lockfiles in the directory should be checked",
			args: []string{"", "./fixtures/locks-many-with-invalid"},
			exit: 0,
		},
		// only the files in the given directories are checked by default (no recursion)
		{
			name: "only the files in the given directories are checked by default (no recursion)",
			args: []string{"", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// nested directories are checked when `--recursive` is passed
		{
			name: "nested directories are checked when `--recursive` is passed",
			args: []string{"", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// .gitignored files
		{
			name: "",
			args: []string{"", "--recursive", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// ignoring .gitignore
		{
			name: "",
			args: []string{"", "--recursive", "--no-ignore", "./fixtures/locks-gitignore"},
			exit: 0,
		},
		// output format: unsupported
		{
			name: "",
			args: []string{"", "--format", "unknown", "./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		// one specific supported lockfile with ignore
		{
			name: "one specific supported lockfile with ignore",
			args: []string{"", "./fixtures/locks-test-ignore/package-lock.json"},
			exit: 0,
		},
		{
			name: "invalid --verbosity value",
			args: []string{"", "--verbosity", "unknown", "./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		{
			name: "verbosity level = error",
			args: []string{"", "--verbosity", "error", "--format", "table", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		{
			name: "verbosity level = info",
			args: []string{"", "--verbosity", "info", "--format", "table", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_LockfileWithExplicitParseAs(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		// unsupported parse-as
		{
			name: "",
			args: []string{"", "-L", "my-file:./fixtures/locks-many/composer.lock"},
			exit: 127,
		},
		// empty is default
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./fixtures/locks-many/composer.lock"),
			},
			exit: 0,
		},
		// empty works as an escape (no fixture because it's not valid on Windows)
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:file"),
			},
			exit: 127,
		},
		{
			name: "",
			args: []string{
				"",
				"-L",
				":" + filepath.FromSlash("./path/to/my:project/package-lock.json"),
			},
			exit: 127,
		},
		// one lockfile with local path
		{
			name: "one lockfile with local path",
			args: []string{"", "--lockfile=go.mod:./fixtures/locks-many/replace-local.mod"},
			exit: 0,
		},
		// when an explicit parse-as is given, it's applied to that file
		{
			name: "",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 0,
		},
		// multiple, + output order is deterministic
		{
			name: "",
			args: []string{
				"",
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 0,
		},
		{
			name: "",
			args: []string{
				"",
				"-L", "yarn.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-yarn.lock"),
				"-L", "package-lock.json:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
			},
			exit: 0,
		},
		// files that error on parsing stop parsable files from being checked
		{
			name: "",
			args: []string{
				"",
				"-L",
				"Cargo.lock:" + filepath.FromSlash("./fixtures/locks-insecure/my-package-lock.json"),
				filepath.FromSlash("./fixtures/locks-insecure"),
				filepath.FromSlash("./fixtures/locks-many"),
			},
			exit: 0,
		},
		// parse-as takes priority, even if it's wrong
		{
			name: "",
			args: []string{
				"",
				"-L",
				"package-lock.json:" + filepath.FromSlash("./fixtures/locks-many/yarn.lock"),
			},
			exit: 0,
		},
		// "apk-installed" is supported
		// TODO : Check why the osv.dev query is failing with a change in ecosystem, for now commenting it as we don't use that path
		// {
		//	name: "",
		//	args: []string{
		//		"",
		//		"-L",
		//		"apk-installed:" + filepath.FromSlash("./fixtures/locks-many/installed"),
		//	},
		//	exit: 0,
		// },
		// "dpkg-status" is supported
		{
			name: "",
			args: []string{
				"",
				"-L",
				"dpkg-status:" + filepath.FromSlash("./fixtures/locks-many/status"),
			},
			exit: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

// TestRun_GithubActions tests common actions the github actions reusable workflow will run
func TestRun_GithubActions(t *testing.T) {
	t.Parallel()

	tests := []cliTestCase{
		{
			name: "scanning osv-scanner custom format",
			args: []string{"", "-L", "osv-scanner:./fixtures/locks-insecure/osv-scanner-flutter-deps.json"},
			exit: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_WithoutHostPathInformation(t *testing.T) {
	t.Parallel()
	tests := []locationTestCase{
		// one specific supported lockfile
		{
			name:          "one specific supported lockfile (relative path)",
			args:          []string{"", "--experimental-only-packages", "--format=cyclonedx-1-5", "--paths-relative-to-scan-dir", "./fixtures/locks-many/yarn.lock"},
			wantExitCode:  0,
			wantFilePaths: []string{"package.json"},
		},
		{
			name:         "Multiple lockfiles (relative path)",
			args:         []string{"", "--experimental-only-packages", "--format=cyclonedx-1-5", "--paths-relative-to-scan-dir", "./fixtures/locks-many"},
			wantExitCode: 0,
			wantFilePaths: []string{
				"package.json",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc := tt
			stdoutBuffer := &bytes.Buffer{}
			stderrBuffer := &bytes.Buffer{}

			ec := run(tc.args, stdoutBuffer, stderrBuffer)

			stdout := stdoutBuffer.String()
			bom := cyclonedx.BOM{}
			err := json.NewDecoder(strings.NewReader(stdout)).Decode(&bom)
			require.NoError(t, err)

			if ec != tc.wantExitCode {
				t.Errorf("cli exited with code %d, not %d", ec, tc.wantExitCode)
			}
			filepaths := gatherFilepath(bom)
			for _, expectedLocation := range tc.wantFilePaths {
				assert.Contains(t, filepaths, expectedLocation)
			}
		})
	}
}

func TestRun_WithCycloneDX15(t *testing.T) {
	t.Parallel()
	args := []string{
		"",
		"-r",
		"--experimental-only-packages",
		"--format=cyclonedx-1-5",
		"--consider-scan-path-as-root",
		"./fixtures/integration-test-locks",
	}

	testCli(t, cliTestCase{
		name: "WithCycloneDX15",
		args: args,
		exit: 0,
	})
}

func TestRun_WithEmptyCycloneDX15(t *testing.T) {
	t.Parallel()
	args := []string{
		"",
		"-r",
		"--experimental-only-packages",
		"--format=cyclonedx-1-5",
		"--consider-scan-path-as-root",
		"./fixtures/locks-empty",
	}

	testCli(t, cliTestCase{
		name: "WithEmptyCycloneDX15",
		args: args,
		exit: 0,
	})
}

func TestRun_WithExplicitParsers(t *testing.T) {
	t.Parallel()
	args := []string{
		"",
		"-r",
		"--experimental-only-packages",
		"--format=cyclonedx-1-5",
		"--consider-scan-path-as-root",
		"--enable-parsers=pom.xml",
		"./fixtures/integration-test-locks",
	}

	testCli(t, cliTestCase{
		name: "WithExplicitParsers",
		args: args,
		exit: 0,
	})
}

func TestRun_YarnPackageOnly(t *testing.T) {
	t.Parallel()
	testCases := []string{
		"v1.22.0",
		"v3.8.7",
		"v4.6.0",
	}

	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt, func(t *testing.T) {
			t.Parallel()
			args := []string{
				"",
				"-r",
				"--experimental-only-packages",
				"--format=cyclonedx-1-5",
				"--consider-scan-path-as-root",
				"./fixtures/integration-yarn/" + tt,
			}
			testCli(t, cliTestCase{
				name: "YarnPackageOnly " + tt,
				args: args,
				exit: 0,
			})
		})
	}
}

func TestRun_NpmPackageOnly(t *testing.T) {
	t.Parallel()
	testCases := []string{
		"v6.14.18",
		"v7.24.2",
		"v8.19.4",
		"v9.9.4",
		"v10.9.0",
	}

	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt, func(t *testing.T) {
			t.Parallel()
			args := []string{
				"",
				"-r",
				"--experimental-only-packages",
				"--format=cyclonedx-1-5",
				"--consider-scan-path-as-root",
				"./fixtures/integration-npm/" + tt,
			}
			testCli(t, cliTestCase{
				name: "Npm package only " + tt,
				args: args,
				exit: 0,
			})
		})
	}
}

func TestRun_WithEncodedLockfile(t *testing.T) {
	t.Parallel()
	testCases := []encodingTestCase{
		{encoding: "UTF-8"},
		{encoding: "UTF-16"},
		{encoding: "Windows-1252"},
	}

	for _, testCase := range testCases {
		tt := testCase
		t.Run(tt.encoding, func(t *testing.T) {
			t.Parallel()
			args := []string{
				"",
				"-r",
				"--experimental-only-packages",
				"--format=cyclonedx-1-5",
				"--paths-relative-to-scan-dir",
				"./fixtures/encoding-integration-test-locks/" + tt.encoding,
			}

			testCli(t, cliTestCase{
				name: tt.encoding,
				args: args,
				exit: 0,
			})
		})
	}
}

func gatherFilepath(bom cyclonedx.BOM) []string {
	locations := make([]string, 0)
	for _, component := range *bom.Components {
		if component.Type != "library" || component.Evidence == nil {
			continue
		}
		for _, location := range *component.Evidence.Occurrences {
			jsonLocation := make(map[string]map[string]interface{})
			_ = json.NewDecoder(strings.NewReader(location.Location)).Decode(&jsonLocation)
			blockLocation := jsonLocation["block"]
			locations = append(locations, blockLocation["file_name"].(string))
		}
	}

	return locations
}

func TestRun_OCIImage(t *testing.T) {
	t.Parallel()
	t.Skip("Skipping until image scanning is reenabled")

	testutility.SkipIfNotAcceptanceTesting(t, "Not consistent on MacOS/Windows")

	tests := []cliTestCase{
		{
			name: "Invalid path",
			args: []string{"", "--experimental-oci-image", "./fixtures/oci-image/no-file-here.tar"},
			exit: 127,
		},
		{
			name: "Alpine 3.10 image tar with 3.18 version file",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-alpine.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using npm with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-npm-empty.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using npm with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-npm-full.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using yarn with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-yarn-empty.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using yarn with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-yarn-full.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using pnpm with no packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-pnpm-empty.tar"},
			exit: 0,
		},
		{
			name: "scanning node_modules using pnpm with some packages",
			args: []string{"", "--experimental-oci-image", "../../internal/image/fixtures/test-node_modules-pnpm-full.tar"},
			exit: 0,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// point out that we need the images to be built and saved separately
			for _, arg := range tt.args {
				if strings.HasPrefix(arg, "../../internal/image/fixtures/") && strings.HasSuffix(arg, ".tar") {
					if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
						t.Fatalf("%s does not exist - have you run scripts/build_test_images.sh?", arg)
					}
				}
			}

			testCli(t, tt)
		})
	}
}

// Tests all subcommands here.
func TestRun_SubCommands(t *testing.T) {
	t.Parallel()
	tests := []cliTestCase{
		// without subcommands
		{
			name: "with no subcommand",
			args: []string{"", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// with scan subcommand
		{
			name: "with scan subcommand",
			args: []string{"", "scan", "./fixtures/locks-many/composer.lock"},
			exit: 0,
		},
		// scan with a flag
		{
			name: "scan with a flag",
			args: []string{"", "scan", "--recursive", "./fixtures/locks-one-with-nested"},
			exit: 0,
		},
		// TODO: add tests for other future subcommands
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testCli(t, tt)
		})
	}
}

func TestRun_InsertDefaultCommand(t *testing.T) {
	t.Parallel()
	commands := []*cli.Command{
		{Name: "default"},
		{Name: "scan"},
	}
	defaultCommand := "default"

	tests := []struct {
		originalArgs []string
		wantArgs     []string
	}{
		// test when default command is specified
		{
			originalArgs: []string{"", "default", "file"},
			wantArgs:     []string{"", "default", "file"},
		},
		// test when command is not specified
		{
			originalArgs: []string{"", "file"},
			wantArgs:     []string{"", "default", "file"},
		},
		// test when command is also a filename
		{
			originalArgs: []string{"", "scan"}, // `scan` exists as a file on filesystem (`./cmd/osv-scanner/scan`)
			wantArgs:     []string{"", "scan"},
		},
		// test when command is not valid
		{
			originalArgs: []string{"", "invalid"},
			wantArgs:     []string{"", "default", "invalid"},
		},
		// test when command is a built-in option
		{
			originalArgs: []string{"", "--version"},
			wantArgs:     []string{"", "--version"},
		},
		{
			originalArgs: []string{"", "-h"},
			wantArgs:     []string{"", "-h"},
		},
		{
			originalArgs: []string{"", "help"},
			wantArgs:     []string{"", "help"},
		},
	}

	for _, tt := range tests {
		tt := tt
		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		argsActual := insertDefaultCommand(tt.originalArgs, commands, defaultCommand, stdout, stderr)
		if !reflect.DeepEqual(argsActual, tt.wantArgs) {
			t.Errorf("Test Failed. Details:\n"+
				"Args (Got):  %s\n"+
				"Args (Want): %s\n", argsActual, tt.wantArgs)
		}
		testutility.NewSnapshot().MatchText(t, normalizeStdStream(t, stdout))
		testutility.NewSnapshot().MatchText(t, normalizeStdStream(t, stderr))
	}
}
