package ruby_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/ruby"

	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/internal/testutil"
	"github.com/DataDog/datadog-sbom-generator/pkg/models"
)

func TestGemfileLockExtractor_ShouldExtract(t *testing.T) {
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
			path: "Gemfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock",
			want: true,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock/file",
			want: false,
		},
		{
			name: "",
			path: "path/to/my/Gemfile.lock.file",
			want: false,
		},
		{
			name: "",
			path: "path.to.my.Gemfile.lock",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := ruby.GemfileLockExtractor{}
			got := e.ShouldExtract(tt.path)
			if got != tt.want {
				t.Errorf("Extract() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseGemfileLock_FileDoesNotExist(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/does-not-exist")

	testutil.ExpectErrIs(t, err, fs.ErrNotExist)
	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGemfileLock_NoSpecSection(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/no-spec-section.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGemfileLock_NoGemSection(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/no-gem-section.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGemfileLock_NoGems(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/no-gems.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackages(t, packages, []extractor.PackageDetails{})
}

func TestParseGemfileLock_OneGem(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/one-gem.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "ast",
			Version:        "2.4.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
	})
}

func TestParseGemfileLock_SomeGems(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/some-gems.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "coderay",
			Version:        "1.1.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "method_source",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "pry",
			Version:        "0.14.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
	})
}

func TestParseGemfileLock_MultipleGems(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/multiple-gems.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "bundler-audit",
			Version:        "0.9.0.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "coderay",
			Version:        "1.1.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "dotenv",
			Version:        "2.7.6",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "method_source",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "pry",
			Version:        "0.14.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "thor",
			Version:        "1.2.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
	})
}

func TestParseGemfileLock_Rails(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/rails.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "actioncable",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actionmailbox",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actionmailer",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actionpack",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actiontext",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actionview",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activejob",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activemodel",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activerecord",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activestorage",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activesupport",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "builder",
			Version:        "3.2.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "concurrent-ruby",
			Version:        "1.1.9",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "crass",
			Version:        "1.0.6",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "digest",
			Version:        "3.1.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "erubi",
			Version:        "1.10.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "globalid",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "i18n",
			Version:        "1.10.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "io-wait",
			Version:        "0.2.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "loofah",
			Version:        "2.14.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "mail",
			Version:        "2.7.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "marcel",
			Version:        "1.0.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "method_source",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "mini_mime",
			Version:        "1.1.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "minitest",
			Version:        "5.15.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "net-imap",
			Version:        "0.2.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "net-pop",
			Version:        "0.1.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "net-protocol",
			Version:        "0.1.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "net-smtp",
			Version:        "0.3.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "nio4r",
			Version:        "2.5.8",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "racc",
			Version:        "1.6.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rack",
			Version:        "2.2.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rack-test",
			Version:        "1.1.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rails",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "rails-dom-testing",
			Version:        "2.0.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rails-html-sanitizer",
			Version:        "1.4.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "railties",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rake",
			Version:        "13.0.6",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "strscan",
			Version:        "3.0.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "thor",
			Version:        "1.2.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "timeout",
			Version:        "0.2.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "tzinfo",
			Version:        "2.0.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "websocket-driver",
			Version:        "0.7.5",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "websocket-extensions",
			Version:        "0.1.5",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "zeitwerk",
			Version:        "2.5.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "nokogiri",
			Version:        "1.13.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
	})
}

func TestParseGemfileLock_Rubocop(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/rubocop.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "ast",
			Version:        "2.4.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "parallel",
			Version:        "1.21.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "parser",
			Version:        "3.1.1.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rainbow",
			Version:        "3.1.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "regexp_parser",
			Version:        "2.2.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rexml",
			Version:        "3.2.5",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rubocop",
			Version:        "1.25.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "rubocop-ast",
			Version:        "1.16.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "ruby-progressbar",
			Version:        "1.11.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "unicode-display_width",
			Version:        "2.1.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
	})
}

func TestParseGemfileLock_HasLocalGem(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/has-local-gem.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "backbone-on-rails",
			Version:        "1.2.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "actionpack",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "actionview",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "activesupport",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "builder",
			Version:        "3.2.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "coffee-script",
			Version:        "2.4.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "coffee-script-source",
			Version:        "1.12.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "concurrent-ruby",
			Version:        "1.1.9",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "crass",
			Version:        "1.0.6",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "eco",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "ejs",
			Version:        "1.1.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "erubi",
			Version:        "1.10.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "execjs",
			Version:        "2.8.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "i18n",
			Version:        "1.10.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "jquery-rails",
			Version:        "4.4.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "loofah",
			Version:        "2.14.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "method_source",
			Version:        "1.0.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "minitest",
			Version:        "5.15.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "racc",
			Version:        "1.6.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rack",
			Version:        "2.2.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rack-test",
			Version:        "1.1.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rails-dom-testing",
			Version:        "2.0.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rails-html-sanitizer",
			Version:        "1.4.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "railties",
			Version:        "7.0.2.2",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "rake",
			Version:        "13.0.6",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "thor",
			Version:        "1.2.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "tzinfo",
			Version:        "2.0.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "zeitwerk",
			Version:        "2.5.4",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "nokogiri",
			Version:        "1.13.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
		{
			Name:           "eco-source",
			Version:        "1.1.0.rc.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
		},
	})
}

func TestParseGemfileLock_HasGitGem(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/has-git-gem.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "hanami-controller",
			Version:        "2.0.0.alpha1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         "027dbe2e56397b534e859fc283990cad1b6addd6",
		},
		{
			Name:           "hanami-utils",
			Version:        "2.0.0.alpha1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         "5904fc9a70683b8749aa2861257d0c8c01eae4aa",
			IsDirect:       true,
		},
		{
			Name:           "concurrent-ruby",
			Version:        "1.1.7",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         "",
		},
		{
			Name:           "rack",
			Version:        "2.2.3",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         "",
		},
		{
			Name:           "transproc",
			Version:        "1.1.1",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			Commit:         "",
		},
	})
}

func TestParseGemfileLock_PlatformSpecificDependencyIsParsed(t *testing.T) {
	t.Parallel()

	packages, err := ruby.ParseGemfileLock("../fixtures/bundler/platform-specific/Gemfile.lock")
	if err != nil {
		t.Errorf("Got unexpected error: %v", err)
	}

	testutil.ExpectPackagesWithoutLocations(t, packages, []extractor.PackageDetails{
		{
			Name:           "zeitwerk",
			Version:        "2.6.0",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
		{
			Name:           "tzinfo-data",
			Version:        "",
			PackageManager: models.Bundler,
			Ecosystem:      models.EcosystemRubyGems,
			IsDirect:       true,
		},
	})
}

func TestParseGemfileLock_SomeGems_BlockLocation(t *testing.T) {
	t.Parallel()

	path, err := filepath.Abs("../fixtures/bundler/some-gems.lock")
	if err != nil {
		t.Fatalf("could not get absolute path: %v", err)
	}

	packages, err := ruby.ParseGemfileLock(path)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	// some-gems.lock has:
	// line 4: "    coderay (1.1.3)"
	// line 5: "    method_source (1.0.0)"
	// line 6: "    pry (0.14.1)"
	assert.Len(t, packages, 3, "expected 3 packages")

	for _, pkg := range packages {
		assert.NotEqual(t, 0, pkg.BlockLocation.Line.Start,
			"expected BlockLocation.Line.Start to be set for package %s", pkg.Name)
		assert.NotEmpty(t, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to be set for package %s", pkg.Name)
		assert.Equal(t, path, pkg.BlockLocation.Filename,
			"expected BlockLocation.Filename to match the lockfile path for package %s", pkg.Name)
	}

	// Verify specific line numbers
	pkgMap := make(map[string]extractor.PackageDetails)
	for _, pkg := range packages {
		pkgMap[pkg.Name] = pkg
	}

	// coderay is at line 4: "    coderay (1.1.3)"
	assert.Equal(t, 4, pkgMap["coderay"].BlockLocation.Line.Start)
	assert.Equal(t, 4, pkgMap["coderay"].BlockLocation.Line.End)
	assert.Equal(t, 1, pkgMap["coderay"].BlockLocation.Column.Start)

	// method_source is at line 5: "    method_source (1.0.0)"
	assert.Equal(t, 5, pkgMap["method_source"].BlockLocation.Line.Start)
	assert.Equal(t, 5, pkgMap["method_source"].BlockLocation.Line.End)

	// pry is at line 6: "    pry (0.14.1)"
	assert.Equal(t, 6, pkgMap["pry"].BlockLocation.Line.Start)
	assert.Equal(t, 6, pkgMap["pry"].BlockLocation.Line.End)

	// Verify path is absolute (from lockfile, not relative)
	assert.True(t, os.IsPathSeparator(path[0]) || filepath.IsAbs(path),
		"path should be absolute")
}
