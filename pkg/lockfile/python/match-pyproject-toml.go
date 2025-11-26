package python

import "github.com/DataDog/datadog-sbom-generator/pkg/lockfile"

type PyprojectTOMLMatcher struct{}

func (m PyprojectTOMLMatcher) GetSourceFile(lockfile lockfile.DepFile) (lockfile.DepFile, error) {
	return lockfile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourcefile lockfile.DepFile, packages []lockfile.PackageDetails) error {
	// pyproject.toml format is almost the same as Pipfile format, we can reuse its matcher
	return PipfileMatcher{}.Match(sourcefile, packages)
}

var _ lockfile.Matcher = PyprojectTOMLMatcher{}
