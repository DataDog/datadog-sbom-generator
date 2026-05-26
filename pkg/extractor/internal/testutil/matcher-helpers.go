package testutil

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/java"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/javascript"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/php"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/python"
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor/ruby"
)

func MockAllMatchers() {
	// package.json
	javascript.YarnExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	javascript.PnpmExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	javascript.NpmExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	// build.gradle
	java.GradleExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	java.GradleVerificationExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	// Pipfile (pipenv)
	python.PipenvExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	// pyproject.toml (poetry)
	python.PoetryExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	// Gemfile (ruby)
	ruby.GemfileExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
	// Composer composer.json
	php.ComposerExtractor.Matchers = []extractor.Matcher{SuccessfulMatcher{}}
}

type SuccessfulMatcher struct{}

func (m SuccessfulMatcher) GetSourceFile(_ extractor.DepFile) (extractor.DepFile, error) {
	return nil, nil
}

func (m SuccessfulMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	return nil
}

var _ extractor.Matcher = SuccessfulMatcher{}

type FailingMatcher struct {
	Error error
}

func (m FailingMatcher) GetSourceFile(f extractor.DepFile) (extractor.DepFile, error) {
	return f, nil
}

func (m FailingMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	return m.Error
}

var _ extractor.Matcher = FailingMatcher{}
