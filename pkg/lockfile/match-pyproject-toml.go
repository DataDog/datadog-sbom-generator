package lockfile

import "github.com/DataDog/datadog-sbom-generator/pkg/models"

type PyprojectTOMLMatcher struct{}

func (m PyprojectTOMLMatcher) GetSourceFile(lockfile DepFile) (DepFile, error) {
	return lockfile.Open("pyproject.toml")
}

func (m PyprojectTOMLMatcher) Match(sourcefile DepFile, packages []models.PackageDetails) error {
	// pyproject.toml format is almost the same as Pipfile format, we can reuse its matcher
	return PipfileMatcher{}.Match(sourcefile, packages)
}

var _ Matcher = PyprojectTOMLMatcher{}
