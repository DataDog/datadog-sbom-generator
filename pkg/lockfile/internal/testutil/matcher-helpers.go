package testutil

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/php"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/lockfile/ruby"
)

func MockAllMatchers() {
	// package.json
	javascript.YarnExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	javascript.PnpmExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	javascript.NpmExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// build.gradle
	java.GradleExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	java.GradleVerificationExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Pipfile (pipenv)
	python.PipenvExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// pyproject.toml (poetry)
	python.PoetryExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Gemfile (ruby)
	ruby.GemfileExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
	// Composer composer.json
	php.ComposerExtractor.Matchers = []lockfile.Matcher{SuccessfulMatcher{}}
}

type SuccessfulMatcher struct{}

func (m SuccessfulMatcher) GetSourceFile(_ lockfile.DepFile) (lockfile.DepFile, error) {
	return nil, nil
}

func (m SuccessfulMatcher) Match(_ lockfile.DepFile, _ []lockfile.PackageDetails) error {
	return nil
}

var _ lockfile.Matcher = SuccessfulMatcher{}

type FailingMatcher struct {
	Error error
}

func (m FailingMatcher) GetSourceFile(f lockfile.DepFile) (lockfile.DepFile, error) {
	return f, nil
}

func (m FailingMatcher) Match(_ lockfile.DepFile, _ []lockfile.PackageDetails) error {
	return m.Error
}

var _ lockfile.Matcher = FailingMatcher{}
