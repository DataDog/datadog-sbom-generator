package python

import (
	"github.com/DataDog/datadog-sbom-generator/pkg/extractor"
)

func (m PyprojectTOMLMatcher) GetSourceFile(depFile extractor.DepFile) (extractor.DepFile, error) {
	return depFile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourceFile extractor.DepFile, packages []extractor.PackageDetails, context extractor.ScanContext) error {
	// pyproject.toml format is almost the same as Pipfile format, we can reuse its matcher
	return PipfileMatcher{}.Match(sourceFile, packages, context)
}

var _ extractor.Matcher = PyprojectTOMLMatcher{}
