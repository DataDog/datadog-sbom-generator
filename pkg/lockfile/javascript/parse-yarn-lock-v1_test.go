package javascript_test

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"

	"github.com/stretchr/testify/assert"
)

func TestParseYarnLock_v1_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseYarnLock("../fixtures/yarn/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_NoPackages(t *testing.T) {
	t.Parallel()

	packages, err := javascript.ParseYarnLock("../fixtures/yarn/empty.v1.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{})
}

func TestParseYarnLock_v1_OnePackage(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/one-package.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

//nolint:paralleltest
func TestParseYarnLock_v1_OnePackage_MatcherFailed(t *testing.T) {
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

	// Mock packageJSONMatcher to fail
	matcherError := errors.New("packageJSONMatcher failed")
	javascript.YarnExtractor.Matchers = []lockfile.Matcher{testutil.FailingMatcher{Error: matcherError}}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/one-package.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
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
	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "balanced-match",
			Version:        "1.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})

	// Reset packageJSONMatcher mock
	testutil.MockAllMatchers()
}

func TestParseYarnLock_v1_TwoPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/two-packages.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "concat-stream",
			Version:        "1.6.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.5.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_WithQuotes(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-quotes.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "concat-stream",
			Version:        "1.6.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.5.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "concat-map",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_MultipleVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/multiple-versions.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "define-properties",
			Version:        "1.1.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.1.3"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "define-property",
			Version:        "0.2.5",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^0.2.5"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "define-property",
			Version:        "1.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "define-property",
			Version:        "2.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.2"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_MultipleConstraints(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/multiple-constraints.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/code-frame",
			Version:        "7.12.13",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/code-frame",
			Version:        "7.12.13",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.12.13"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "domelementtype",
			Version:        "1.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "domelementtype",
			Version:        "1.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.3.1"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_ScopedPackages(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/scoped-packages.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/code-frame",
			Version:        "7.12.11",
			PackageManager: models.Yarn,
			TargetVersions: []string{"7.12.11"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@babel/compat-data",
			Version:        "7.14.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.13.11"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_WithPrerelease(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-prerelease.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "css-tree",
			Version:        "1.0.0-alpha.37",
			PackageManager: models.Yarn,
			TargetVersions: []string{"1.0.0-alpha.37"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "gensync",
			Version:        "1.0.0-beta.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0-beta.2"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "node-fetch",
			Version:        "3.0.0-beta.9",
			PackageManager: models.Yarn,
			TargetVersions: []string{"3.0.0-beta.9"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "1.20.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.1.7"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "1.20.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.10.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "1.20.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.12.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "1.20.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.14.2"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "1.20.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.20.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "resolve",
			Version:        "2.0.0-next.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.0.0-next.3"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_WithBuildString(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-build-string.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_Commits(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/commits.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "mine1",
			Version:        "1.0.0-alpha.37",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+ssh://git@github.com:G-Rath/npm-git-repo-2#0a2d2506c1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine2",
			Version:        "0.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"G-Rath/npm-git-repo-2#0a2d2506c1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine3",
			Version:        "1.2.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"G-Rath/npm-git-repo-1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "094e581aaf927d010e4b61d706ba584551dac502",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine4",
			Version:        "0.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{
				"git+ssh://git@github.com:G-Rath/npm-git-repo-2#aa3bdfcb",
			},
			Ecosystem:    models.EcosystemNPM,
			Commit:       "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine4",
			Version:        "0.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{
				"git+ssh://git@github.com:G-Rath/npm-git-repo-2#another-branch",
			},
			Ecosystem:    models.EcosystemNPM,
			Commit:       "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "mine4",
			Version:        "0.0.4",
			PackageManager: models.Yarn,
			TargetVersions: []string{"G-Rath/npm-git-repo-2#another-branch"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-package",
			Version:        "1.8.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+https://git@github.com/my-org/my-package.git#v1.8.3"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "b3bd3f1b3dad036e671251f5258beaae398f983a",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@bower_components/angular-animate",
			Version:        "1.4.14",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git://github.com/angular/bower-angular-animate.git#~1.4.0"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "e7f778fc054a086ba3326d898a00fa1bc78650a8",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@bower_components/alertify",
			Version:        "0.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"fabien-d/alertify.js-shim#^0.3.10"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "e7b6c46d76604d297c389d830817b611c9a8f17c",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "minimist",
			Version:        "0.0.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"ssh://github.com/substack/minimist.git#0.0.8"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "3754568bfd43a841d2d72d7fb54598635aea8fa4",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "minimist",
			Version:        "0.0.8",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.8"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "3754568bfd43a841d2d72d7fb54598635aea8fa4",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "bats-assert",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/bats-core/bats-assert"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "4bdd58d3fbcdce3209033d44d884e87add1d8405",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "bats-support",
			Version:        "0.3.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/bats-core/bats-support"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "d140a65044b2d6810381935ae7f0c94c7023c8c3",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "bats",
			Version:        "1.5.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/bats-core/bats-core#master"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "172580d2ce19ee33780b5f1df817bbddced43789",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "vue",
			Version:        "2.6.12",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://github.com/vuejs/vue.git#v2.6.12"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "kit",
			Version:        "1.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+https://bitbucket.org/kettlelogic/kit.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "5b6830c0252eb73c6024d40a8ff5106d3023a2a6",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "casadistance",
			Version:        "1.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"git+ssh://git@bitbucket.org/casasoftag/casadistance.git"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "f0308391f0c50104182bfb2332a53e4e523a4603",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "babel-preset-php",
			Version:        "1.1.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"gitlab:kornelski/babel-preset-php#master"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "is-number",
			Version:        "2.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"github:jonschlinkert/is-number#master"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "is-number",
			Version:        "5.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"https://dummy-token@github.com/jonschlinkert/is-number.git#master"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "af885e2e890b9ef0875edd2b117305119ee5bdc5",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_Files(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/files.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "etag",
			Version:        "1.8.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "filedep",
			Version:        "1.2.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"../../correct/path/filedep"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "lodash",
			Version:        "1.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.3.1"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "other_package",
			Version:        "0.0.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"./deps/other_package"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "sprintf-js",
			Version:        "0.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"./mocks/sprintf-js"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "sprintf-js",
			Version:        "0.0.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"~1.0.2"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "etag",
			Version:        "1.8.0",
			PackageManager: models.Yarn,
			TargetVersions: []string{"./deps/etag"},
			Ecosystem:      models.EcosystemNPM,
			Commit:         "",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	expected[3].Dependencies = append(expected[3].Dependencies, &expected[2])
	expected[3].Dependencies = append(expected[3].Dependencies, &expected[0])

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v1_WithAliases(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-aliases.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []lockfile.PackageDetails{
		{
			Name:           "@babel/helper-validator-identifier",
			Version:        "7.22.20",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "6.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "ansi-regex",
			Version:        "5.0.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_v1_WithDependencies(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/with-dependencies-v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "domino",
			Version:        "2.1.6+git",
			Commit:         "",
			TargetVersions: []string{"https://github.com/angular/domino.git#f2435fe1f9f7c91ade0bd472c4723e5eacd7d19a"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "tslib",
			Version:        "2.6.2",
			TargetVersions: []string{"^2.3.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}
	expected[0].Dependencies = append(expected[0].Dependencies, &expected[1])

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v1_WithResolution(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/resolution.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "@typescript-eslint/parser",
			Version:        "2.34.0",
			TargetVersions: []string{"^2.26.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "my-custom-parser",
			Version:        "3.10.1",
			TargetVersions: []string{"^3.10.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v1_WithEmptyVersions(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/empty-version.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "d3",
			Version:        "abc123def456789",
			TargetVersions: []string{"~3.5.6"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Commit:         "abc123def456789",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "lodash",
			Version:        "4a2b9e1e5f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
			TargetVersions: []string{"^4.0.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Commit:         "4a2b9e1e5f6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "normal-package",
			Version:        "1.0.0",
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

// Test case: workspace-same-lib-and-version demonstrates shared dependencies:
// Root: no dependencies
// workspace-1: semver ^7.3.2
// workspace-2: semver ^7.3.2 (same as workspace-1)
func TestParseYarnLock_v1_WorkspacesSameLibSameVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/yarn-v1.lock"))
	// path := filepath.FromSlash("/private/tmp/sbom-test-repos/sca-testing-electron/spec/yarn.lock")
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-same-lib-and-version/package.json")
	// sourceFile, err := lockfile.OpenLocalDepFile("/private/tmp/sbom-test-repos/sca-testing-electron/spec/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// Even tho
	workspace1path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-and-version/workspace-1/package.json"))
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod", "prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}

// Test case: workspace-same-lib-different-version demonstrates semver conflicts:
// Root: semver ^7.3.4
// workspace-1: semver ^7.3.3
// workspace-2: semver ^6.0.0
func TestParseYarnLock_v1_WorkspacesSameLibDifferentVersion(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/yarn-v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-same-lib-different-version/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/package.json"))
	workspace1path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/workspace-1/package.json"))
	workspace2path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-same-lib-different-version/nested/workspace-2/package.json"))
	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.4"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 5, End: 23},
				Filename: rootPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 6, End: 12},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 10, End: 10},
				Column:   models.Position{Start: 16, End: 22},
				Filename: rootPath,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.3"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace2path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace2path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}

// Test case: workspace-complex demonstrates multi-workspace dependency conflicts:
// Root: semver ^4.3.0, group-dependencies 0.0.11
// workspace-1: semver ^7.3.2, picocolors ^0.2.1
// workspace-2: semver ^6.3.0
// workspace-3: semver ^5.0.0, picocolors ^1.1.1
func TestParseYarnLock_v1_WorkspacesComplex(t *testing.T) {
	t.Parallel()

	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/yarn-v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	sourceFile, err := lockfile.OpenLocalDepFile("../fixtures/package-json/workspace-complex/package.json")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}
	err = packageJSONMatcher.Match(sourceFile, packages, testutil.GetTestContext())
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	rootPath := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/package.json"))
	workspace1Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-1/package.json"))
	workspace2Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/nested/workspace-2/package.json"))
	workspace3Path := filepath.FromSlash(filepath.Join(dir, "../fixtures/package-json/workspace-complex/workspace-3/package.json"))

	testutil.ExpectPackages(t, packages, []lockfile.PackageDetails{
		{
			Name:           "group-dependencies",
			Version:        "0.0.11",
			PackageManager: models.Yarn,
			TargetVersions: []string{"0.0.11"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 5, End: 35},
				Filename: rootPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 6, End: 24},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 14, End: 14},
				Column:   models.Position{Start: 28, End: 34},
				Filename: rootPath,
			},
			IsDirect:  true,
			DepGroups: []string{"dev"},
			Dependencies: []*lockfile.PackageDetails{
				{
					Name:           "colors",
					Version:        "1.4.0",
					TargetVersions: []string{"^1.4.0"},
					PackageManager: models.Yarn,
					Ecosystem:      models.EcosystemNPM,
					DepGroups:      []string{"dev"},
					Dependencies:   make([]*lockfile.PackageDetails, 0),
				},
			},
		},
		{
			Name:           "colors",
			Version:        "1.4.0",
			TargetVersions: []string{"^1.4.0"},
			PackageManager: models.Yarn,
			Ecosystem:      models.EcosystemNPM,
			BlockLocation:  models.FilePosition{},
			IsDirect:       false, // is a dependency of group-dependencies@0.0.11
			DepGroups:      []string{"dev"},
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "4.3.6",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^4.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 5, End: 23},
				Filename: rootPath,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 6, End: 12},
				Filename: rootPath,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 11, End: 11},
				Column:   models.Position{Start: 16, End: 22},
				Filename: rootPath,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "picocolors",
			Version:        "0.2.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^0.2.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: workspace1Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: workspace1Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: workspace1Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "7.7.3",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^7.3.2"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace1Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace1Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace1Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "6.3.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^6.3.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace2Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace2Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace2Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "picocolors",
			Version:        "1.1.1",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^1.1.1"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 5, End: 27},
				Filename: workspace3Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 6, End: 16},
				Filename: workspace3Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 5, End: 5},
				Column:   models.Position{Start: 20, End: 26},
				Filename: workspace3Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "semver",
			Version:        "5.7.2",
			PackageManager: models.Yarn,
			TargetVersions: []string{"^5.0.0"},
			Ecosystem:      models.EcosystemNPM,
			BlockLocation: models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 5, End: 23},
				Filename: workspace3Path,
			},
			NameLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 6, End: 12},
				Filename: workspace3Path,
			},
			VersionLocation: &models.FilePosition{
				Line:     models.Position{Start: 6, End: 6},
				Column:   models.Position{Start: 16, End: 22},
				Filename: workspace3Path,
			},
			IsDirect:     true,
			DepGroups:    []string{"prod"},
			Dependencies: make([]*lockfile.PackageDetails, 0),
		},
	})
}

func TestParseYarnLock_JSON_v9(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/json-format.v9.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	expected := []lockfile.PackageDetails{
		{
			Name:           "@aashutoshrathi/word-wrap",
			Version:        "1.2.6",
			TargetVersions: []string{"^1.2.3"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "@actions/core",
			Version:        "1.10.1",
			TargetVersions: []string{"1.10.1"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}

func TestParseYarnLock_v1_WithEmptyVersionNoGit(t *testing.T) {
	t.Parallel()
	dir, err := os.Getwd()
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	path := filepath.FromSlash(filepath.Join(dir, "../fixtures/yarn/empty-version-no-git.v1.lock"))
	packages, err := javascript.ParseYarnLock(path)
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	// broken-package has empty version with no git commit in resolution
	// It should still be parsed but with empty version (triggering warning at runtime)
	expected := []lockfile.PackageDetails{
		{
			Name:           "broken-package",
			Version:        "", // Empty - no git commit to extract
			TargetVersions: []string{"^1.0.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
		{
			Name:           "working-package",
			Version:        "2.0.0",
			TargetVersions: []string{"^2.0.0"},
			Ecosystem:      models.EcosystemNPM,
			PackageManager: models.Yarn,
			Dependencies:   make([]*lockfile.PackageDetails, 0),
		},
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, expected)
}
