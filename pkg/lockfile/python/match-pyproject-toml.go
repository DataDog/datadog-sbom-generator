package python

import "github.com/DataDog/datadog-sbom-generator/pkg/lockfile"

func (m PyprojectTOMLMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourceFile lockfile.DepFile, packages []lockfile.PackageDetails, context lockfile.ScanContext) error {
	// pyproject.toml format is almost the same as Pipfile format, we can reuse its matcher
	return PipfileMatcher{}.Match(sourceFile, packages, context)
}

var _ lockfile.Matcher = PyprojectTOMLMatcher{}
