package lockfile

import "github.com/DataDog/datadog-sbom-generator/pkg/models"

type Matcher interface {
	GetSourceFile(lockfile DepFile) (DepFile, error)
	Match(sourceFile DepFile, packages []models.PackageDetails) error
}

func matchWithFile(lockfile DepFile, packages []models.PackageDetails, matcher Matcher) error {
	sourceFile, err := matcher.GetSourceFile(lockfile)
	if err != nil {
		return err
	}

	if sourceFile == nil {
		return nil
	}

	return matcher.Match(sourceFile, packages)
}
